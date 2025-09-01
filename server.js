// server.js — Meta Webhook + Kommo (atribución write-once + fallbacks)

import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();

// ====== MIDDLEWARE: cuerpo crudo para validar firma HMAC ======
app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// ====== ENV (Meta) ======
const VERIFY_TOKEN = (process.env.META_VERIFY_TOKEN || "").trim();
const APP_SECRET   = process.env.META_APP_SECRET;

// ====== ENV (Kommo) ======
const KOMMO = {
  base: (process.env.KOMMO_BASE || "").replace(/\/+$/, ""),
  clientId: process.env.KOMMO_CLIENT_ID,
  clientSecret: process.env.KOMMO_CLIENT_SECRET,
  redirectUri: process.env.KOMMO_REDIRECT_URI,
  accessToken: process.env.KOMMO_ACCESS_TOKEN || null,
  refreshToken: process.env.KOMMO_REFRESH_TOKEN || null,
};

// ====== DIAGNÓSTICO ======
app.get("/",  (_, res) => res.status(200).send("up"));
app.get("/health", (_, res) => res.status(200).send("ok"));

// ====== WEBHOOK VERIFY (GET) ======
app.get("/webhook", (req, res) => {
  const mode = (req.query["hub.mode"] || "").trim();
  const token = (req.query["hub.verify_token"] || "").trim();
  const challenge = req.query["hub.challenge"];

  console.log("VERIFY_TOKEN set?:", !!VERIFY_TOKEN, "len:", VERIFY_TOKEN.length);
  console.log("Incoming token prefix/suffix:", token.slice(0,4), "...", token.slice(-4));

  if (mode === "subscribe" && token && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// ====== FIRMA HMAC (POST) ======
function isValidSignature(req) {
  if (!APP_SECRET) return true; // solo para pruebas (en prod, exige APP_SECRET)
  const received = req.get("x-hub-signature-256") || "";
  const expected = "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  if (received.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected)); }
  catch { return false; }
}

// ====== OAUTH KOMMO: CALLBACK code -> tokens (1 vez si vas por OAuth) ======
app.get("/kommo/oauth/callback", async (req, res) => {
  try {
    const code = req.query.code;
    const r = await fetch(`${KOMMO.base}/oauth2/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: KOMMO.clientId,
        client_secret: KOMMO.clientSecret,
        grant_type: "authorization_code",
        code,
        redirect_uri: KOMMO.redirectUri,
      }),
    });
    const data = await r.json();
    if (!r.ok) return res.status(400).send(data);

    KOMMO.accessToken  = data.access_token;
    KOMMO.refreshToken = data.refresh_token;
    console.log("KOMMO TOKENS (copia a Render y redepliega):", {
      access_token: KOMMO.accessToken,
      refresh_token: KOMMO.refreshToken,
    });
    return res.status(200).send("OK. Revisa logs de Render y copia access_token / refresh_token a Environment.");
  } catch (e) {
    console.error("OAuth callback error:", e);
    return res.sendStatus(500);
  }
});

// ====== REFRESH TOKEN KOMMO ======
async function kommoRefresh() {
  const r = await fetch(`${KOMMO.base}/oauth2/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: KOMMO.clientId,
      client_secret: KOMMO.clientSecret,
      grant_type: "refresh_token",
      refresh_token: KOMMO.refreshToken,
      redirect_uri: KOMMO.redirectUri,
    }),
  });
  const data = await r.json();
  if (!r.ok) throw new Error(`Refresh failed: ${JSON.stringify(data)}`);
  KOMMO.accessToken  = data.access_token;
  KOMMO.refreshToken = data.refresh_token;
  console.log("KOMMO TOKENS REFRESHED:", {
    access_token: KOMMO.accessToken,
    refresh_token: KOMMO.refreshToken,
  });
}

// ====== REQUEST WRAPPER KOMMO (retry en 401) ======
async function kommoRequest(path, options = {}, retry = true) {
  const r = await fetch(`${KOMMO.base}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${KOMMO.accessToken}`,
      ...(options.headers || {}),
    },
  });
  if (r.status === 401 && retry && KOMMO.refreshToken) {
    await kommoRefresh();
    return kommoRequest(path, options, false);
  }
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`Kommo ${r.status}: ${t}`);
  }
  try { return await r.json(); } catch { return null; }
}

// ====== FIELD IDs (Kommo LEAD) ======
const FIELDS = {
  LEAD: {
    CTWA_CLID:          2097583,
    CAMPAIGN_ID:        2097585,
    ADSET_ID:           2097587,
    AD_ID:              2097589,
    PLATFORM:           2097591,
    CHANNEL_SOURCE:     2097593,
    FIRST_TS:           2097597, // UNIX segundos
    LAST_TS:            2097599, // UNIX segundos
    THREAD_ID:          2097601,
    ENTRY_OWNER_ID:     2097603, // WA: phone_number_id / FB: page_id
    CAMPAIGN_NAME:      2097605,
    MEDIA_BUDGET_HINT:  2097607,
    DEAL_AMOUNT:        2097609,
  }
};

// ====== HELPERS ======
const unix = (ts) => (ts ? Number(ts) : null);  // WA manda segundos (string) → Number
const normE164 = (p) => (p ? (p.startsWith("+") ? p : `+${p}`) : null); // ★ normaliza tel

// Convierte payload -> custom_fields_values (enviando fechas como UNIX)
function leadCFV(p) {
  const out = [];
  const add = (id, v) => (v !== null && v !== undefined && v !== "") &&
    out.push({ field_id: id, values: [{ value: v }] });
  add(FIELDS.LEAD.CTWA_CLID,          p.ctwa_clid);
  add(FIELDS.LEAD.CAMPAIGN_ID,        p.campaign_id);
  add(FIELDS.LEAD.ADSET_ID,           p.adset_id);
  add(FIELDS.LEAD.AD_ID,              p.ad_id);
  add(FIELDS.LEAD.PLATFORM,           p.platform);
  add(FIELDS.LEAD.CHANNEL_SOURCE,     p.channel_source);
  add(FIELDS.LEAD.FIRST_TS,           p.first_message_unix);
  add(FIELDS.LEAD.LAST_TS,            p.last_message_unix);
  add(FIELDS.LEAD.THREAD_ID,          p.thread_id);
  add(FIELDS.LEAD.ENTRY_OWNER_ID,     p.entry_owner_id);
  add(FIELDS.LEAD.CAMPAIGN_NAME,      p.campaign_name);
  add(FIELDS.LEAD.MEDIA_BUDGET_HINT,  p.media_budget_hint);
  add(FIELDS.LEAD.DEAL_AMOUNT,        p.deal_amount);
  return out;
}

// ---- Helpers para leer y congelar atribución ----
function cfvToMap(custom_fields_values = []) {
  const m = new Map();
  for (const cf of custom_fields_values) {
    const id = cf.field_id;
    const v  = cf.values?.[0]?.value;
    if (id != null) m.set(id, v);
  }
  return m;
}
const num = (v) => (v == null || v === "" ? null : Number(v) || null);

// Congela (write-once) los campos de atribución y mantiene fechas coherentes
function mergeAttribution(existingCFV = [], incomingPayload) {
  const m = cfvToMap(existingCFV);
  const out = { ...incomingPayload };

  // WRITE-ONCE
  const keep = (fid, key) => {
    const have = m.get(fid);
    if (have != null && have !== "") out[key] = have;
  };

  keep(FIELDS.LEAD.CTWA_CLID,      "ctwa_clid");
  keep(FIELDS.LEAD.CAMPAIGN_ID,    "campaign_id");
  keep(FIELDS.LEAD.ADSET_ID,       "adset_id");
  keep(FIELDS.LEAD.AD_ID,          "ad_id");
  keep(FIELDS.LEAD.PLATFORM,       "platform");
  keep(FIELDS.LEAD.CHANNEL_SOURCE, "channel_source");

  // Fechas (UNIX segundos): first = mínimo; last = máximo
  const firstOld = num(m.get(FIELDS.LEAD.FIRST_TS));
  const lastOld  = num(m.get(FIELDS.LEAD.LAST_TS));
  const firstNew = num(incomingPayload.first_message_unix);
  const lastNew  = num(incomingPayload.last_message_unix);

  out.first_message_unix = (firstOld != null && firstNew != null)
    ? Math.min(firstOld, firstNew)
    : (firstOld ?? firstNew ?? null);

  out.last_message_unix = (lastOld != null && lastNew != null)
    ? Math.max(lastOld, lastNew)
    : (lastOld ?? lastNew ?? null);

  return out;
}

// ====== KOMMO: búsqueda/altas/actualizaciones ======
async function findLeadByCtwa(clid) {
  if (!clid) return null;
  const q = encodeURIComponent(clid);
  const res = await kommoRequest(`/api/v4/leads?query=${q}&limit=25`, { method: "GET" });
  const leads = res?._embedded?.leads || [];
  return leads.find(l =>
    (l.custom_fields_values || []).some(cf => cf.field_id === FIELDS.LEAD.CTWA_CLID &&
      cf.values?.[0]?.value === clid)
  ) || null;
}

// Busca contacto por teléfono y devuelve su lead más reciente
async function findLeadByPhone(phoneE164) {
  if (!phoneE164) return null;
  const q = encodeURIComponent(phoneE164);
  // contacto por teléfono
  const res = await kommoRequest(`/api/v4/contacts?query=${q}&limit=10`, { method: "GET" });
  const contact = res?._embedded?.contacts?.[0];
  if (!contact) return null;

  // leads del contacto
  const det = await kommoRequest(`/api/v4/contacts/${contact.id}?with=leads`, { method: "GET" });
  const leads = det?._embedded?.leads || [];
  if (!leads.length) return null;

  // más reciente
  leads.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
  return leads[0];
}

// ★ NUEVO: buscar por threadId (último recurso)
async function findLeadByThreadId(tid) {
  if (!tid) return null;
  const q = encodeURIComponent(tid);
  const res = await kommoRequest(`/api/v4/leads?query=${q}&limit=25`, { method: "GET" });
  const leads = res?._embedded?.leads || [];
  return leads.find(l =>
    (l.custom_fields_values || []).some(cf => cf.field_id === FIELDS.LEAD.THREAD_ID &&
      cf.values?.[0]?.value === tid)
  ) || null;
}

async function createLeadOnly({ name, payload }) {
  const body = { add: [{ name: name || "Lead desde chat", custom_fields_values: leadCFV(payload) }] };
  const res = await kommoRequest(`/api/v4/leads`, { method: "POST", body: JSON.stringify(body) });
  return res?._embedded?.leads?.[0] || null;
}

async function updateLeadCFV(leadId, payload) {
  const body = [{ id: leadId, custom_fields_values: leadCFV(payload) }];
  await kommoRequest(`/api/v4/leads`, { method: "PATCH", body: JSON.stringify(body) });
}

// Upsert inteligente + write-once de atribución
// ★ Orden completo: CTWA → TELÉFONO → THREAD
async function upsertLeadSmart({ payload, phoneE164, threadId }) {
  let lead = null;

  if (payload.ctwa_clid) lead = await findLeadByCtwa(payload.ctwa_clid);
  if (!lead && phoneE164) lead = await findLeadByPhone(phoneE164);
  if (!lead && threadId)  lead = await findLeadByThreadId(threadId);

  if (lead) {
    const merged = mergeAttribution(lead.custom_fields_values, payload);
    await updateLeadCFV(lead.id, merged);
    return { lead, created: false };
  }

  const created = await createLeadOnly({
    name: `Chat ${payload.platform?.toUpperCase() || "MSG"} ${phoneE164 ? `(${phoneE164})` : ""}`.trim(),
    payload
  });
  return { lead: created, created: true };
}

// ====== WEBHOOK EVENTS (POST) ======
app.post("/webhook", async (req, res) => {
  if (!isValidSignature(req)) return res.sendStatus(401);

  try {
    // WhatsApp e Instagram usan "changes"; Messenger usa "entry[].messaging[]"
    const object = req.body.object;

    // ──────────────── WhatsApp ────────────────
    const entry  = req.body.entry?.[0];
    const change = entry?.changes?.[0];
    const value  = change?.value;

    const messagingProduct = (value?.messaging_product || "").toLowerCase();

    if (messagingProduct === "whatsapp") {
      const waMsg     = value?.messages?.[0];
      const referral  = waMsg?.referral || value?.referral || null;
      const ctwaClid  = referral?.ctwa_clid || referral?.click_id || null;

      const metadata  = value?.metadata || {};
      const phoneNumberId   = metadata.phone_number_id || entry?.id || null; // ★ usar metadata primero
      // const displayPhone    = metadata.display_phone_number || null;       // si luego quieres guardarlo

      const userPhone = normE164(waMsg?.from); // ★ normalizado
      const ts = unix(waMsg?.timestamp);

      const payload = {
        platform: "whatsapp",
        channel_source: referral ? "ctwa" : "whatsapp",
        ctwa_clid:   ctwaClid,
        campaign_id: referral?.campaign_id || null,
        adset_id:    referral?.adset_id    || null,
        ad_id:       referral?.ad_id       || null,

        first_message_unix: ts,
        last_message_unix:  ts,

        thread_id:      waMsg?.id || null,
        entry_owner_id: phoneNumberId, // ★ guardamos phone_number_id en tu campo WABA/Page/IG ID

        campaign_name:     null,
        media_budget_hint: null,
        deal_amount:       null,
      };

      console.log("INBOUND WA:", JSON.stringify(req.body, null, 2));
      console.log("CTWA_CLICK_ID:", ctwaClid || "(no referral)");
      console.log("USER PHONE:", userPhone || "(desconocido)");

      // Upsert con orden completo (CTWA → TEL → THREAD)
      const { lead, created } = await upsertLeadSmart({
        payload,
        phoneE164: userPhone,
        threadId: payload.thread_id
      });
      console.log(`LEAD Kommo ${created ? "creado" : "actualizado"}:`, lead?.id || "(sin id)");
      return res.sendStatus(200);
    }

    // ──────────────── Messenger (Page) ────────────────
    if (object === "page") {
      const pageEntry = req.body.entry?.[0];
      const msg = pageEntry?.messaging?.[0];
      if (!msg) return res.sendStatus(200);

      const pageId = pageEntry?.id || null;
      const mid    = msg?.message?.mid || msg?.delivery?.mids?.[0] || null;
      const referral = msg?.referral || msg?.postback?.referral || null;

      const payload = {
        platform: "messenger",
        channel_source: referral ? "ctm" : "messenger",
        ctwa_clid: null, // Messenger no usa ctwa_clid

        first_message_unix: Math.floor(Date.now()/1000),
        last_message_unix:  Math.floor(Date.now()/1000),

        thread_id:      mid,
        entry_owner_id: pageId, // guardamos page_id en tu campo WABA/Page/IG ID
      };

      console.log("INBOUND MSG (Messenger):", JSON.stringify(req.body, null, 2));

      const { lead, created } = await upsertLeadSmart({
        payload,
        phoneE164: null,           // normalmente no tenemos teléfono aquí
        threadId: payload.thread_id
      });
      console.log(`LEAD Kommo ${created ? "creado" : "actualizado"}:`, lead?.id || "(sin id)");
      return res.sendStatus(200);
    }

    // (Si más adelante activas Instagram DM, aquí podemos añadir la rama "object === 'instagram'").

    return res.sendStatus(200);
  } catch (e) {
    console.error("Webhook handling error:", e);
    return res.sendStatus(500);
  }
});

// ====== START SERVER ======
app.listen(process.env.PORT || 3000, () => {
  console.log("Webhook escuchando...");
});
