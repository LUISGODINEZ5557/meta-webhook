// server.js — Webhook Meta -> Kommo (UPDATE-ONLY, sin creación)
// - Enriquecimiento de atribución (write-once) para WA/Messenger (IG opcional)
// - Matching determinista: TELÉFONO → CTWA → THREAD
// - Reintentos cortos para esperar a que Kommo cree el lead por su lado

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

  if (mode === "subscribe" && token && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// ====== FIRMA HMAC (POST) ======
function isValidSignature(req) {
  if (!APP_SECRET) return true; // para pruebas locales
  const received = req.get("x-hub-signature-256") || "";
  const expected = "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  if (received.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected)); }
  catch { return false; }
}

// ====== OAUTH KOMMO (opcional) ======
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
    console.log("KOMMO TOKENS:", {
      access_token: KOMMO.accessToken,
      refresh_token: KOMMO.refreshToken,
    });
    return res.status(200).send("OK. Copia tokens al Environment y redepliega.");
  } catch (e) {
    console.error("OAuth callback error:", e);
    return res.sendStatus(500);
  }
});

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
}

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
    ENTRY_OWNER_ID:     2097603, // WA: phone_number_id; FB/IG: page_id/ig_id
    CAMPAIGN_NAME:      2097605,
    MEDIA_BUDGET_HINT:  2097607,
    DEAL_AMOUNT:        2097609,
  }
};

// ====== HELPERS ======
const unix = (ts) => (ts ? Number(ts) : null);
const normE164 = (p) => (p ? (p.startsWith("+") ? p : `+${p}`) : null);
const wait = (ms) => new Promise(r => setTimeout(r, ms));
const RETRIES = 4;   // nº de intentos de búsqueda
const BACKOFF = 600; // ms entre intentos

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

// write-once + fechas coherentes
function mergeAttribution(existingCFV = [], incomingPayload) {
  const m = cfvToMap(existingCFV);
  const out = { ...incomingPayload };

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

// ====== BÚSQUEDAS ======
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

async function findLeadByPhone(phoneE164) {
  if (!phoneE164) return null;
  // probamos con +E164 y sin +
  const candidates = [phoneE164, phoneE164.startsWith("+") ? phoneE164.slice(1) : `+${phoneE164}`];
  for (const qv of candidates) {
    const q = encodeURIComponent(qv);
    const res = await kommoRequest(`/api/v4/contacts?query=${q}&limit=10`, { method: "GET" });
    const contact = res?._embedded?.contacts?.[0];
    if (!contact) continue;

    const det = await kommoRequest(`/api/v4/contacts/${contact.id}?with=leads`, { method: "GET" });
    const leads = det?._embedded?.leads || [];
    if (!leads.length) continue;

    leads.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
    return leads[0];
  }
  return null;
}

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

async function updateLeadCFV(leadId, payload) {
  const body = [{ id: leadId, custom_fields_values: leadCFV(payload) }];
  await kommoRequest(`/api/v4/leads`, { method: "PATCH", body: JSON.stringify(body) });
}

// ====== UPDATE-ONLY (NO CREATE) con reintentos ======
async function updateExistingLeadOnly({ payload, phoneE164, threadId }) {
  for (let i = 0; i < RETRIES; i++) {
    let lead = null;

    // 1) teléfono
    if (phoneE164) lead = await findLeadByPhone(phoneE164);
    // 2) ctwa
    if (!lead && payload.ctwa_clid) lead = await findLeadByCtwa(payload.ctwa_clid);
    // 3) thread
    if (!lead && threadId) lead = await findLeadByThreadId(threadId);

    if (lead) {
      const merged = mergeAttribution(lead.custom_fields_values, payload);
      await updateLeadCFV(lead.id, merged);
      return { lead, updated: true, attempt: i + 1 };
    }
    // espera y reintenta (Kommo puede tardar unos ms en crear/ligar el lead)
    await wait(BACKOFF);
  }
  return { lead: null, updated: false, attempt: RETRIES };
}

// ====== WEBHOOK (POST) ======
app.post("/webhook", async (req, res) => {
  if (!isValidSignature(req)) return res.sendStatus(401);

  try {
    const object = req.body.object;

    // ───────────── WhatsApp (WA Cloud) ─────────────
    const entry  = req.body.entry?.[0];
    const change = entry?.changes?.[0];
    const value  = change?.value;
    const product = (value?.messaging_product || "").toLowerCase();

    if (product === "whatsapp") {
      const waMsg     = value?.messages?.[0];
      if (!waMsg) { return res.sendStatus(200); }

      const referral  = waMsg?.referral || value?.referral || null;
      const ctwaClid  = referral?.ctwa_clid || referral?.click_id || null;

      const metadata  = value?.metadata || {};
      const phoneNumberId = metadata.phone_number_id || entry?.id || null;

      const userPhone = normE164(waMsg?.from);
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
        entry_owner_id: phoneNumberId,

        campaign_name:     null,
        media_budget_hint: null,
        deal_amount:       null,
      };

      const { lead, updated, attempt } = await updateExistingLeadOnly({
        payload,
        phoneE164: userPhone,
        threadId: payload.thread_id
      });
      console.log(updated
        ? `UPDATED lead ${lead?.id} (WA) in attempt ${attempt}`
        : `NO MATCH → NO CREATE (WA). phone=${userPhone} ctwa=${ctwaClid} thread=${payload.thread_id}`
      );
      return res.sendStatus(200);
    }

    // ───────────── Messenger (Page) ─────────────
    if (object === "page") {
      const pageEntry = req.body.entry?.[0];
      const msg = pageEntry?.messaging?.[0];
      if (!msg) return res.sendStatus(200);

      const pageId = pageEntry?.id || null;
      const mid    = msg?.message?.mid || msg?.delivery?.mids?.[0] || msg?.postback?.mid || null;
      const referral = msg?.referral || msg?.postback?.referral || null;

      const now = Math.floor(Date.now()/1000);
      const payload = {
        platform: "messenger",
        channel_source: referral ? "ctm" : "messenger",
        ctwa_clid: null, // Messenger no trae ctwa_clid estándar

        first_message_unix: now,
        last_message_unix:  now,

        thread_id:      mid || msg?.sender?.id || null, // fallback a PSID
        entry_owner_id: pageId,
      };

      const { lead, updated, attempt } = await updateExistingLeadOnly({
        payload,
        phoneE164: null,
        threadId: payload.thread_id
      });
      console.log(updated
        ? `UPDATED lead ${lead?.id} (MSG) in attempt ${attempt}`
        : `NO MATCH → NO CREATE (MSG). thread=${payload.thread_id}`
      );
      return res.sendStatus(200);
    }

    // (Opcional) Instagram DM: añadir rama similar usando sender.id como thread_id

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
