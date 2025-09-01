import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();

// Body crudo para validar firma HMAC y poder leer el JSON
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
  const received = req.get("x-hub-signature-256") || "";
  const expected = "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  if (received.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected)); }
  catch { return false; }
}

// ====== OAUTH KOMMO: CALLBACK PARA CANJEAR CODE -> TOKENS (úsalo 1 vez) ======
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

    KOMMO.accessToken = data.access_token;
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
  KOMMO.accessToken = data.access_token;
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
    FIRST_TS:           2097597,
    LAST_TS:            2097599,
    THREAD_ID:          2097601,
    ENTRY_OWNER_ID:     2097603,
    CAMPAIGN_NAME:      2097605,
    MEDIA_BUDGET_HINT:  2097607,
    DEAL_AMOUNT:        2097609,
  }
};

// ====== HELPERS ======
const isoFromTs = (ts) =>
  ts ? new Date(Number(ts) * 1000).toISOString().slice(0,19).replace("T"," ") : null;

function leadCFV(p) {
  const out = [];
  const add = (id, v) => (v != null && v !== "") && out.push({ field_id: id, values: [{ value: v }] });
  add(FIELDS.LEAD.CTWA_CLID,          p.ctwa_clid);
  add(FIELDS.LEAD.CAMPAIGN_ID,        p.campaign_id);
  add(FIELDS.LEAD.ADSET_ID,           p.adset_id);
  add(FIELDS.LEAD.AD_ID,              p.ad_id);
  add(FIELDS.LEAD.PLATFORM,           p.platform);
  add(FIELDS.LEAD.CHANNEL_SOURCE,     p.channel_source);
  add(FIELDS.LEAD.FIRST_TS,           p.first_message_iso);
  add(FIELDS.LEAD.LAST_TS,            p.last_message_iso);
  add(FIELDS.LEAD.THREAD_ID,          p.thread_id);
  add(FIELDS.LEAD.ENTRY_OWNER_ID,     p.entry_owner_id);
  add(FIELDS.LEAD.CAMPAIGN_NAME,      p.campaign_name);
  add(FIELDS.LEAD.MEDIA_BUDGET_HINT,  p.media_budget_hint);
  add(FIELDS.LEAD.DEAL_AMOUNT,        p.deal_amount);
  return out;
}

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

async function createLeadOnly({ name, payload }) {
  const body = { add: [{ name: name || "Lead desde chat", custom_fields_values: leadCFV(payload) }] };
  const res = await kommoRequest(`/api/v4/leads`, { method: "POST", body: JSON.stringify(body) });
  return res?._embedded?.leads?.[0] || null;
}

async function updateLeadCFV(leadId, payload) {
  const body = [{ id: leadId, custom_fields_values: leadCFV(payload) }];
  await kommoRequest(`/api/v4/leads`, { method: "PATCH", body: JSON.stringify(body) });
}

async function upsertLeadByCtwa({ payload }) {
  let lead = await findLeadByCtwa(payload.ctwa_clid);
  if (lead) {
    await updateLeadCFV(lead.id, payload);
    return lead;
  }
  return await createLeadOnly({
    name: `Chat ${payload.platform?.toUpperCase() || "MSG"}`,
    payload
  });
}

// ====== WEBHOOK EVENTS (POST) ======
app.post("/webhook", async (req, res) => {
  if (!isValidSignature(req)) return res.sendStatus(401);

  try {
    const entry  = req.body.entry?.[0];
    const change = entry?.changes?.[0];
    const value  = change?.value;

    // Plataforma (WA/Messenger/IG) — Meta manda "whatsapp" para WA Cloud
    const platform = (value?.messaging_product || "whatsapp").toLowerCase();

    // WhatsApp: valores comunes
    const waMsg    = value?.messages?.[0];
    const referral = waMsg?.referral || value?.referral || null;
    const ctwaClid = referral?.ctwa_clid || referral?.click_id || null;

    const payload = {
      platform,
      channel_source: referral ? "ctwa" : platform,
      ctwa_clid:   ctwaClid,
      campaign_id: referral?.campaign_id || null,
      adset_id:    referral?.adset_id    || null,
      ad_id:       referral?.ad_id       || null,

      first_message_iso: isoFromTs(waMsg?.timestamp),
      last_message_iso:  isoFromTs(waMsg?.timestamp),

      thread_id:      waMsg?.id || null,
      entry_owner_id: entry?.id || null,

      // opcionales (puedes llenarlos luego desde tu BI/Marketing API):
      campaign_name:     null,
      media_budget_hint: null,
      deal_amount:       null,
    };

    console.log("INBOUND EVENT:", JSON.stringify(req.body, null, 2));
    console.log("CTWA_CLICK_ID:", ctwaClid || "(no referral)");

    // Guardar en Kommo (upsert por ctwa_clid)
    const lead = await upsertLeadByCtwa({ payload });
    console.log("LEAD Kommo actualizado/creado:", lead?.id || "(sin id)");

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
