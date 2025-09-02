// server.js — Meta Webhook -> Kommo (update-only, write-once attribution)

import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();

// ========= RAW BODY para validar HMAC =========
app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// ========= ENV (Meta) =========
const VERIFY_TOKEN = (process.env.META_VERIFY_TOKEN || "").trim();
const APP_SECRET   = process.env.META_APP_SECRET; // si no está, firma se omite (solo pruebas)

// ========= ENV (Kommo) =========
const KOMMO = {
  base: (process.env.KOMMO_BASE || "").replace(/\/+$/, ""),
  clientId: process.env.KOMMO_CLIENT_ID,
  clientSecret: process.env.KOMMO_CLIENT_SECRET,
  redirectUri: process.env.KOMMO_REDIRECT_URI,
  accessToken: process.env.KOMMO_ACCESS_TOKEN || null,
  refreshToken: process.env.KOMMO_REFRESH_TOKEN || null,
};

// ========= DIAGNÓSTICO =========
app.get("/",  (_, res) => res.status(200).send("up"));
app.get("/health", (_, res) => res.status(200).send("ok"));

// ========= VERIFY (GET) =========
app.get("/webhook", (req, res) => {
  const mode = (req.query["hub.mode"] || "").trim();
  const token = (req.query["hub.verify_token"] || "").trim();
  const challenge = req.query["hub.challenge"];

  console.log("[VERIFY] expected.len =", VERIFY_TOKEN.length, " incoming.prefix/suffix:",
    token.slice(0,4), "...", token.slice(-4));

  if (mode === "subscribe" && token && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// ========= HMAC (POST) =========
function isValidSignature(req) {
  if (!APP_SECRET) return true; // Sólo para pruebas
  const received = req.get("x-hub-signature-256") || "";
  const expected = "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  if (received.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected)); }
  catch { return false; }
}

// ========= OAuth Kommo (1 vez para obtener tokens) =========
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
    console.log("[KOMMO OAUTH] Copia estos tokens a Render env y redeploy:", {
      access_token: KOMMO.accessToken,
      refresh_token: KOMMO.refreshToken,
    });
    return res.status(200).send("OK. Revisa logs y copia access_token/refresh_token a Environment.");
  } catch (e) {
    console.error("[KOMMO OAUTH] error:", e);
    return res.sendStatus(500);
  }
});

// ========= Refresh Token Kommo =========
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
  console.log("[KOMMO] tokens refrescados");
}

// ========= Wrapper Kommo (retry 401) =========
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

// ========= FIELD IDs (Kommo LEAD) =========
const FIELDS = {
  LEAD: {
    CTWA_CLID:          2097583,
    CAMPAIGN_ID:        2097585,
    ADSET_ID:           2097587,
    AD_ID:              2097589,
    PLATFORM:           2097591,
    CHANNEL_SOURCE:     2097593,
    FIRST_TS:           2097597, // Fecha/Hora (UNIX seconds)
    LAST_TS:            2097599, // Fecha/Hora (UNIX seconds)
    THREAD_ID:          2097601,
    ENTRY_OWNER_ID:     2097603,
    CAMPAIGN_NAME:      2097605,
    MEDIA_BUDGET_HINT:  2097607,
    DEAL_AMOUNT:        2097609,
  }
};

// ========= Helpers de mapeo =========
const unix = (ts) => (ts ? Number(ts) : null); // WhatsApp manda string en segundos
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

// Construye custom_fields_values a partir del payload
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

// Fusiona atribución (write-once) + fechas coherentes
function mergeAttribution(existingCFV = [], incomingPayload) {
  const m = cfvToMap(existingCFV);
  const out = { ...incomingPayload };

  const keep = (fid, key) => {
    const have = m.get(fid);
    if (have != null && have !== "") out[key] = have;
  };

  // Campos write-once
  keep(FIELDS.LEAD.CTWA_CLID,      "ctwa_clid");
  keep(FIELDS.LEAD.CAMPAIGN_ID,    "campaign_id");
  keep(FIELDS.LEAD.ADSET_ID,       "adset_id");
  keep(FIELDS.LEAD.AD_ID,          "ad_id");
  keep(FIELDS.LEAD.PLATFORM,       "platform");
  keep(FIELDS.LEAD.CHANNEL_SOURCE, "channel_source");

  // Fechas (mínimo / máximo)
  const firstOld = num(m.get(FIELDS.LEAD.FIRST_TS));
  const lastOld  = num(m.get(FIELDS.LEAD.LAST_TS));
  const firstNew = num(incomingPayload.first_message_unix);
  const lastNew  = num(incomingPayload.last_message_unix);

  const firstMerged = (firstOld != null && firstNew != null)
    ? Math.min(firstOld, firstNew)
    : (firstOld ?? firstNew ?? null);

  const lastMerged = (lastOld != null && lastNew != null)
    ? Math.max(lastOld, lastNew)
    : (lastOld ?? lastNew ?? null);

  console.log("[TS] first_old:", firstOld, " first_new:", firstNew, "=>", firstMerged);
  console.log("[TS] last_old :", lastOld,  " last_new :", lastNew,  "=>", lastMerged);

  out.first_message_unix = firstMerged;
  out.last_message_unix  = lastMerged;

  return out;
}

// ========= Kommo utils (leer lead completo) =========
async function getLeadById(leadId) {
  if (!leadId) return null;
  return await kommoRequest(`/api/v4/leads/${leadId}`, { method: "GET" });
}

// Buscar por CTWA (y luego traer el lead completo)
async function findLeadByCtwa(clid) {
  if (!clid) return null;
  const q = encodeURIComponent(clid);
  const res = await kommoRequest(`/api/v4/leads?query=${q}&limit=25`, { method: "GET" });
  const list = res?._embedded?.leads || [];
  const hit = list.find(l =>
    (l.custom_fields_values || []).some(cf =>
      cf.field_id === FIELDS.LEAD.CTWA_CLID && cf.values?.[0]?.value === clid
    )
  );
  if (!hit?.id) return null;
  return await getLeadById(hit.id);
}

// Buscar por teléfono: toma lead más reciente del contacto y lo trae completo
async function findLeadByPhone(phoneE164) {
  if (!phoneE164) return null;

  const q = encodeURIComponent(phoneE164);
  const res = await kommoRequest(`/api/v4/contacts?query=${q}&limit=10`, { method: "GET" });
  const contact = res?._embedded?.contacts?.[0];
  if (!contact) return null;

  const det = await kommoRequest(`/api/v4/contacts/${contact.id}?with=leads`, { method: "GET" });
  const leads = det?._embedded?.leads || [];
  if (!leads.length) return null;

  leads.sort((a, b) => (b.updated_at || b.created_at || 0) - (a.updated_at || a.created_at || 0));
  const chosen = leads[0];
  if (!chosen?.id) return null;

  return await getLeadById(chosen.id);
}

// Patch de CFVs del lead
async function updateLeadCFV(leadId, payload) {
  const body = [{ id: leadId, custom_fields_values: leadCFV(payload) }];
  await kommoRequest(`/api/v4/leads`, { method: "PATCH", body: JSON.stringify(body) });
}

// Upsert (solo update): intenta CTWA, luego teléfono. Si no hay match, NO crea.
async function updateExistingLead({ payload, phoneE164 }) {
  let lead = null;

  if (payload.ctwa_clid) {
    lead = await findLeadByCtwa(payload.ctwa_clid);
    if (lead) console.log("[MATCH] por CTWA en lead", lead.id);
  }

  if (!lead && phoneE164) {
    lead = await findLeadByPhone(phoneE164);
    if (lead) console.log("[MATCH] por teléfono en lead", lead.id);
  }

  if (!lead) {
    console.log("[NO MATCH] No se encontró lead por CTWA ni teléfono. No se crea.");
    return { lead: null, updated: false };
  }

  const merged = mergeAttribution(lead.custom_fields_values, payload);
  await updateLeadCFV(lead.id, merged);
  return { lead, updated: true };
}

// ========= WEBHOOK (POST) =========
app.post("/webhook", async (req, res) => {
  if (!isValidSignature(req)) return res.sendStatus(401);

  try {
    const entry  = req.body.entry?.[0];
    const change = entry?.changes?.[0];
    const value  = change?.value;

    // Plataforma (whatsapp/messenger/instagram)
    const platform = (value?.messaging_product || "whatsapp").toLowerCase();

    // WhatsApp payload (lo más común en CTWA)
    const waMsg     = value?.messages?.[0]; // puede ser undefined en eventos de estado
    const referral  = waMsg?.referral || value?.referral || null;
    const ctwaClid  = referral?.ctwa_clid || referral?.click_id || null;
    const userPhone = waMsg?.from || null; // E.164 cuando es WhatsApp

    // Marca de tiempo (WA manda seconds como string)
    const msgTs = unix(waMsg?.timestamp) || Math.floor(Date.now() / 1000);

    const payload = {
      platform,                                     // whatsapp | messenger | instagram
      channel_source: referral ? "ctwa" : platform, // ctwa cuando venga referral
      ctwa_clid:   ctwaClid,
      campaign_id: referral?.campaign_id || null,
      adset_id:    referral?.adset_id    || null,
      ad_id:       referral?.ad_id       || null,

      // Timestamps coherentes
      first_message_unix: msgTs,
      last_message_unix:  msgTs,

      thread_id:      waMsg?.id || null,
      entry_owner_id: entry?.id || null,

      // Campos opcionales preparados
      campaign_name:     null,
      media_budget_hint: null,
      deal_amount:       null,
    };

    console.log("=== INBOUND EVENT ===");
    console.log("platform:", platform, " ctwa:", ctwaClid || "(no)");
    console.log("userPhone:", userPhone || "(n/a)");
    console.log("payload base:", payload);

    // Solo actualizar, nunca crear
    const { lead, updated } = await updateExistingLead({ payload, phoneE164: userPhone });
    console.log(updated
      ? `[UPDATED] Lead ${lead?.id}`
      : "[SKIP] No lead encontrado; no se creó ninguno."
    );

    return res.sendStatus(200);
  } catch (e) {
    console.error("[WEBHOOK ERROR]", e);
    return res.sendStatus(500);
  }
});

// ========= START =========
app.listen(process.env.PORT || 3000, () => {
  console.log("Webhook escuchando...");
});
