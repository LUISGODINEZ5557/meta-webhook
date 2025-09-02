// server.js — Meta Webhook + Kommo (write-once, sin crear leads, con búsqueda de teléfono robusta)

import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();

app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// ===== META =====
const VERIFY_TOKEN = (process.env.META_VERIFY_TOKEN || "").trim();
const APP_SECRET   = process.env.META_APP_SECRET;

// ===== KOMMO =====
const KOMMO = {
  base: (process.env.KOMMO_BASE || "").replace(/\/+$/, ""),
  clientId: process.env.KOMMO_CLIENT_ID,
  clientSecret: process.env.KOMMO_CLIENT_SECRET,
  redirectUri: process.env.KOMMO_REDIRECT_URI,
  accessToken: process.env.KOMMO_ACCESS_TOKEN || null,
  refreshToken: process.env.KOMMO_REFRESH_TOKEN || null,
};

app.get("/",  (_, res) => res.status(200).send("up"));
app.get("/health", (_, res) => res.status(200).send("ok"));

// ========== VERIFY GET ==========
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

// ========== HMAC ==========
function isValidSignature(req) {
  if (!APP_SECRET) return true; // solo pruebas
  const received = req.get("x-hub-signature-256") || "";
  const expected = "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  if (received.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected)); }
  catch { return false; }
}

// ========== OAUTH CALLBACK ==========
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
    console.log("KOMMO TOKENS (copia en Render y redeploy):", {
      access_token: KOMMO.accessToken,
      refresh_token: KOMMO.refreshToken,
    });
    return res.status(200).send("OK. Copia tokens desde logs a Environment y redepliega.");
  } catch (e) {
    console.error("OAuth callback error:", e);
    return res.sendStatus(500);
  }
});

// ========== REFRESH & REQUEST ==========
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
  console.log("KOMMO TOKENS REFRESHED");
}

async function kommoRequest(path, options = {}, retry = true) {
  const url = `${KOMMO.base}${path}`;
  const r = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${KOMMO.accessToken}`,
      "User-Agent": "meta-webhook-kommo/1.0",
      ...(options.headers || {}),
    },
  });
  if (r.status === 401 && retry && KOMMO.refreshToken) {
    console.warn("401 en Kommo. Intentando refresh...");
    await kommoRefresh();
    return kommoRequest(path, options, false);
  }
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    console.error(`Kommo ${r.status} ${url} ::`, t);
    throw new Error(`Kommo ${r.status}: ${t}`);
  }
  try { return await r.json(); } catch { return null; }
}

// ========== CAMPOS (IDs que me diste) ==========
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

// ========== HELPERS ==========
const unix = (ts) => (ts ? Number(ts) : null);
const num  = (v) => (v == null || v === "" ? null : Number(v) || null);
const asArray = (v) => Array.isArray(v) ? v : [];

function cfvToMap(custom_fields_values) {
  const m = new Map();
  for (const cf of asArray(custom_fields_values)) {
    const id = cf.field_id;
    const v  = cf.values?.[0]?.value;
    if (id != null) m.set(id, v);
  }
  return m;
}

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

// ========== NORMALIZACIÓN DE TELÉFONO ==========
function phoneCandidates(raw) {
  if (!raw) return [];
  const digits = String(raw).replace(/\D+/g, "");
  const cands = new Set();

  // WhatsApp 'from' ya suele venir E164 sin '+'
  cands.add(digits);                 // 5213312345678
  cands.add("+" + digits);           // +5213312345678
  // Últimos 10 (Mx) — útil si Kommo guarda así
  if (digits.length >= 10) {
    const last10 = digits.slice(-10);
    cands.add(last10);
    cands.add("+52" + last10);       // ajusta si tu país no es MX
  }
  return Array.from(cands);
}

// ========== LECTURA / UPDATE EN KOMMO ==========
async function getLeadById(id) {
  if (!id) return null;
  try {
    return await kommoRequest(`/api/v4/leads/${id}`, { method: "GET" });
  } catch (e) {
    console.error("getLeadById error:", e.message || e);
    return null;
  }
}

async function findLeadByCtwa(clid) {
  if (!clid) return null;
  const q = encodeURIComponent(clid);
  const res = await kommoRequest(`/api/v4/leads?query=${q}&limit=25`, { method: "GET" });
  const leads = res?._embedded?.leads || [];
  const match = leads.find(l =>
    asArray(l.custom_fields_values).some(cf => cf.field_id === FIELDS.LEAD.CTWA_CLID &&
      cf.values?.[0]?.value === clid)
  );
  if (!match) return null;
  const full = await getLeadById(match.id);
  return full || match;
}

async function findLeadByPhone(rawPhone) {
  const tries = phoneCandidates(rawPhone);
  if (!tries.length) return null;

  console.log("[PHONE MATCH] Probar variantes:", tries.join(", "));
  for (const qRaw of tries) {
    const q = encodeURIComponent(qRaw);
    try {
      const res = await kommoRequest(`/api/v4/contacts?query=${q}&limit=10`, { method: "GET" });
      const contact = res?._embedded?.contacts?.[0];
      if (!contact) continue;

      const det = await kommoRequest(`/api/v4/contacts/${contact.id}?with=leads`, { method: "GET" });
      const leads = det?._embedded?.leads || [];
      if (!leads.length) continue;

      leads.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
      const latest = leads[0];
      const full = await getLeadById(latest.id);
      console.log("[PHONE MATCH] Encontrado contacto", contact.id, "lead", latest.id);
      return full || latest;
    } catch (e) {
      console.warn("Búsqueda por teléfono falló con", qRaw, "->", e.message || e);
    }
  }
  return null;
}

async function updateLeadCFV(leadId, payload) {
  const cfv = leadCFV(payload);
  console.log("[PATCH] lead", leadId, "custom_fields_values:", JSON.stringify(cfv));
  const body = [{ id: leadId, custom_fields_values: cfv }];
  await kommoRequest(`/api/v4/leads`, { method: "PATCH", body: JSON.stringify(body) });
  console.log("[PATCH OK] lead", leadId);
}

// Solo ACTUALIZA si encuentra (no crea)
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
    console.log("[NO MATCH] Sin coincidencia por CTWA ni teléfono. No se crea.");
    return { updated: false, leadId: null };
  }

  const merged = mergeAttribution(lead.custom_fields_values, payload);
  await updateLeadCFV(lead.id, merged);
  return { updated: true, leadId: lead.id };
}

// ========== WEBHOOK POST ==========
app.post("/webhook", async (req, res) => {
  if (!isValidSignature(req)) return res.sendStatus(401);

  try {
    const entry  = req.body.entry?.[0];
    const change = entry?.changes?.[0];
    const value  = change?.value;

    const product = (value?.messaging_product || "").toLowerCase();
    if (product && product !== "whatsapp") {
      console.log("Evento no-WhatsApp recibido; se ignora.");
      return res.sendStatus(200);
    }

    const waMsg = value?.messages?.[0];
    if (!waMsg) {
      console.log("Sin messages[0]; nada que hacer.");
      return res.sendStatus(200);
    }

    const referral  = waMsg?.referral || value?.referral || null;
    const ctwaClid  = referral?.ctwa_clid || referral?.click_id || null;
    const userPhone = waMsg?.from || null;
    const ts        = unix(waMsg?.timestamp);

    const payload = {
      platform:       "whatsapp",
      channel_source: referral ? "ctwa" : "whatsapp",
      ctwa_clid:      ctwaClid,
      campaign_id:    referral?.campaign_id || null,
      adset_id:       referral?.adset_id    || null,
      ad_id:          referral?.ad_id       || null,
      first_message_unix: ts,
      last_message_unix:  ts,
      thread_id:      waMsg?.id || null,
      entry_owner_id: entry?.id || null,
      campaign_name:     null,
      media_budget_hint: null,
      deal_amount:       null,
    };

    console.log("=== INBOUND EVENT ===");
    console.log("platform:", payload.platform, "ctwa:", ctwaClid ? "sí" : "(no)");
    console.log("phone (raw WA):", userPhone || "(desconocido)");

    const { updated, leadId } = await updateExistingLead({ payload, phoneE164: userPhone });
    if (updated) console.log("[OK] Lead actualizado:", leadId);
    else         console.log("[SKIP] No se actualizó (sin match).");

    return res.sendStatus(200);
  } catch (e) {
    console.error("[WEBHOOK ERROR]", e);
    return res.sendStatus(500);
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Webhook escuchando...");
});
