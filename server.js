// server.js — Meta Webhook + Kommo (LLT: sin refresh), write-once,
// respuesta inmediata, retries 5/10/15 min (coalescencia),
// fast-probe opcional y Ads enrichment opcional.
// Mejora: búsqueda por teléfono robusta (MX 521→52) + fallback en /leads?query
// + logs de conteo para diagnóstico.

import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();
app.use(bodyParser.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));

/* ================= META ================= */
const VERIFY_TOKEN = (process.env.META_VERIFY_TOKEN || "").trim();
const APP_SECRET   = process.env.META_APP_SECRET;

/* ===== Graph API (Ads enrichment opcional) ===== */
const GRAPH_VER  = process.env.META_GRAPH_VERSION || "v20.0";
const GRAPH_BASE = `https://graph.facebook.com/${GRAPH_VER}`;
const ADS_TOKEN  = process.env.META_ADS_TOKEN || null;

async function graphGet(path, params = {}) {
  if (!ADS_TOKEN) return null;
  const qs  = new URLSearchParams({ access_token: ADS_TOKEN, ...params }).toString();
  const url = `${GRAPH_BASE}${path}?${qs}`;
  const r   = await fetch(url);
  const txt = await r.text();
  if (!r.ok) {
    console.error("[ADS API ERROR]", r.status, txt);
    throw new Error(`Graph ${r.status}: ${txt}`);
  }
  try { return JSON.parse(txt); } catch { return null; }
}

/** Completa campaign/adset/ad (y nombre campaña) usando el ID más específico disponible */
async function enrichFromAds(ref = {}) {
  if (!ADS_TOKEN) return {};
  const out = {};
  try {
    if (ref.ad_id) {
      const ad = await graphGet(`/${ref.ad_id}`, {
        fields: "id,name,adset_id,campaign_id,adset{name},campaign{name}"
      });
      if (ad?.id) out.ad_id = ad.id;
      if (ad?.adset_id) out.adset_id = ad.adset_id;
      if (ad?.campaign_id) out.campaign_id = ad.campaign_id;
      out.campaign_name = ad?.campaign?.name || out.campaign_name || null;
    } else if (ref.adset_id) {
      const adset = await graphGet(`/${ref.adset_id}`, {
        fields: "id,name,campaign_id,campaign{name}"
      });
      if (adset?.id) out.adset_id = adset.id;
      if (adset?.campaign_id) out.campaign_id = adset.campaign_id;
      out.campaign_name = adset?.campaign?.name || out.campaign_name || null;
    } else if (ref.campaign_id) {
      const camp = await graphGet(`/${ref.campaign_id}`, { fields: "id,name" });
      if (camp?.id) out.campaign_id = camp.id;
      out.campaign_name = camp?.name || out.campaign_name || null;
    }
  } catch (e) {
    console.error("[ADS ENRICH ERROR]", e.message || e);
  }
  for (const k of Object.keys(out)) {
    if (out[k] === null || out[k] === undefined || out[k] === "") delete out[k];
  }
  return out;
}

/* ================= KOMMO (LLT: sin refresh) ================= */
const KOMMO = {
  base: (process.env.KOMMO_BASE || "").replace(/\/+$/, ""),
  accessToken: process.env.KOMMO_ACCESS_TOKEN || "", // token de larga duración
};

/* ================= RETRIES ANTI-RACE ================= */
const ANTI_RACE = { enabled: true, delayMs: 5 * 60 * 1000, attempts: 3 };
const FAST_PROBE = process.env.FAST_PROBE === "1";
const pendingRetries = new Map(); // key -> { timer, attempt }

/* ================= DIAGNÓSTICO ================= */
app.get("/",  (_, res) => res.status(200).send("up"));
app.get("/health", (_, res) => res.status(200).send("ok"));

/* ================= VERIFY (GET) ================= */
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

/* ================= HMAC (POST) ================= */
function isValidSignature(req) {
  if (!APP_SECRET) return true; // pruebas
  const received = req.get("x-hub-signature-256") || "";
  const expected = "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  if (!received) { console.error("[HMAC] faltó header x-hub-signature-256"); return false; }
  if (received.length !== expected.length) {
    console.error("[HMAC] len mismatch. recv:", received.slice(0,15), "... exp:", expected.slice(0,15), "...");
    return false;
  }
  try {
    const ok = crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected));
    if (!ok) console.error("[HMAC] firma inválida. recv:", received.slice(0,30), " exp:", expected.slice(0,30));
    return ok;
  } catch (e) {
    console.error("[HMAC ERROR]", e.message||e);
    return false;
  }
}

/* ================= KOMMO REQUEST (LLT; con backoff) ================= */
function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }

async function kommoRequest(path, options = {}) {
  const url = `${KOMMO.base}${path}`;
  let attempt = 0;
  let delay = 1000;

  while (true) {
    attempt++;
    const started = Date.now();
    const r = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${KOMMO.accessToken}`,
        "User-Agent": "meta-webhook-kommo/LLT-1.1",
        ...(options.headers || {}),
      },
    });
    const ms = Date.now() - started;

    if (r.status === 401) {
      const t = await r.text().catch(() => "");
      console.error(`Kommo 401 (token inválido/expirado). Reemplaza KOMMO_ACCESS_TOKEN. Resp: ${t}`);
      throw new Error(`Kommo 401: ${t}`);
    }

    if ((r.status === 429 || (r.status >= 500 && r.status <= 599)) && attempt <= 5) {
      const retryAfter = Number(r.headers.get("Retry-After")) || 0;
      const wait = Math.max(retryAfter * 1000, delay);
      console.warn(`Kommo ${r.status} ${url} (${ms}ms). Retry #${attempt} in ${wait}ms`);
      await sleep(wait);
      delay = Math.min(delay * 2, 30_000);
      continue;
    }

    if (!r.ok) {
      const t = await r.text().catch(() => "");
      console.error(`Kommo ${r.status} ${url} (${ms}ms)::`, t);
      throw new Error(`Kommo ${r.status}: ${t}`);
    }

    try { return await r.json(); } catch { return null; }
  }
}

/* ================= CAMPOS (IDs Kommo) ================= */
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

/* ================= HELPERS ================= */
const unix = (ts) => (ts ? Number(ts) : null);
const num  = (v) => (v == null || v === "" ? null : Number(v) || null);
const asArray = (v) => Array.isArray(v) ? v : [];

/** Normalización robusta de teléfono (MX incluido: 521→52) */
function phoneCandidates(raw) {
  if (!raw) return [];
  const digits = String(raw).replace(/\D+/g, "");
  const cands = new Set();

  // Base
  cands.add(digits);          // 5216144947274
  cands.add("+" + digits);    // +5216144947274

  // MX: si arranca con 521, agrega 52 (sin '1')
  if (digits.startsWith("521") && digits.length >= 12) {
    const mx52 = "52" + digits.slice(3); // 526144947274
    cands.add(mx52);
    cands.add("+" + mx52);
    cands.add("00" + mx52);   // 00526144947274 (algunos CRMs europeos)
  }

  // últimos 10: 6144947274, +52 + últimos 10, y 52 + últimos 10 (sin '+')
  if (digits.length >= 10) {
    const last10 = digits.slice(-10);
    cands.add(last10);
    cands.add("+52" + last10);
    cands.add("52" + last10);
  }

  return Array.from(cands);
}

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

/* ================= LECTURA / UPDATE EN KOMMO ================= */
async function getLeadById(id) {
  if (!id) return null;
  try { return await kommoRequest(`/api/v4/leads/${id}`, { method: "GET" }); }
  catch (e) { console.error("getLeadById error:", e.message || e); return null; }
}

async function findLeadByCtwa(clid) {
  if (!clid) return null;
  const q = encodeURIComponent(clid);
  const res = await kommoRequest(`/api/v4/leads?query=${q}&limit=25`, { method: "GET" });
  const leads = res?._embedded?.leads || [];
  console.log(`[SEARCH] leads?query=CTWA got ${leads.length}`);
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
      const contacts = res?._embedded?.contacts || [];
      console.log(`[SEARCH] contacts?query=${qRaw} -> ${contacts.length}`);
      const contact = contacts[0];
      if (!contact) continue;

      const det = await kommoRequest(`/api/v4/contacts/${contact.id}?with=leads`, { method: "GET" });
      const leads = det?._embedded?.leads || [];
      console.log(`[SEARCH] contact ${contact.id} leads -> ${leads.length}`);
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

/** NUEVO: fallback directo a /leads?query=tel por si el teléfono no está aún en el Contact */
async function findLeadByPhoneInLeads(rawPhone) {
  const tries = phoneCandidates(rawPhone);
  for (const qRaw of tries) {
    const q = encodeURIComponent(qRaw);
    try {
      const res = await kommoRequest(`/api/v4/leads?query=${q}&limit=25`, { method: "GET" });
      const leads = res?._embedded?.leads || [];
      console.log(`[SEARCH] leads?query=${qRaw} -> ${leads.length}`);
      if (!leads.length) continue;
      leads.sort((a,b)=>(b.updated_at||0)-(a.updated_at||0));
      const full = await getLeadById(leads[0].id);
      if (full) {
        console.log("[PHONE->LEADS] match lead", full.id, "con query", qRaw);
        return full;
      }
    } catch (e) {
      console.warn("[PHONE->LEADS] fallo con", qRaw, "->", e.message||e);
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

/* ===== Intento único de update (sin crear) ===== */
async function tryUpdateOnce({ payload, phoneE164 }) {
  let lead = null;

  if (payload.ctwa_clid) {
    lead = await findLeadByCtwa(payload.ctwa_clid);
    if (lead) console.log("[MATCH] por CTWA en lead", lead.id);
  }

  if (!lead && phoneE164) {
    lead = await findLeadByPhone(phoneE164); // via contacts
    if (lead) console.log("[MATCH] por teléfono (contacts) en lead", lead.id);
  }

  if (!lead && phoneE164) {
    lead = await findLeadByPhoneInLeads(phoneE164); // NUEVO fallback directo en leads
    if (lead) console.log("[MATCH] por teléfono (leads?query) en lead", lead.id);
  }

  if (!lead) {
    console.log("[NO MATCH] Aún no existe lead/contacto en Kommo.");
    return false;
  }

  const merged = mergeAttribution(lead.custom_fields_values, payload);
  await updateLeadCFV(lead.id, merged);
  return true;
}

/* ===== Programación de reintentos a 5/10/15 min con coalescencia + fast-probe opcional ===== */
function scheduleAntiRace(key, payload, phoneE164) {
  if (!ANTI_RACE.enabled) return;

  const existing = pendingRetries.get(key);
  if (existing?.timer) {
    console.log(`[ANTI-RACE] Ya hay un intento programado para ${key}; omito duplicar.`);
    return;
  }

  if (FAST_PROBE) {
    const t20 = setTimeout(async () => {
      pendingRetries.delete(key);
      try {
        const ok = await tryUpdateOnce({ payload, phoneE164 });
        if (ok) { console.log(`[FAST_PROBE] Éxito para ${key}`); return; }
      } catch (e) {
        console.warn("[FAST_PROBE ERROR]", e.message || e);
      }
      _scheduleSeries(key, payload, phoneE164, 1); // 5/10/15
    }, 20_000);
    pendingRetries.set(key, { timer: t20, attempt: 0 });
    return;
  }

  _scheduleSeries(key, payload, phoneE164, 1);
}

function _scheduleSeries(key, payload, phoneE164, attempt) {
  if (attempt > ANTI_RACE.attempts) {
    pendingRetries.delete(key);
    console.warn(`[ANTI-RACE] Abandonado ${key} tras ${attempt - 1} intentos`);
    return;
  }
  const delay = ANTI_RACE.delayMs; // 5 min
  console.log(`[ANTI-RACE] Intento #${attempt} para ${key} en ${Math.round(delay/60000)} min`);
  const timer = setTimeout(async () => {
    pendingRetries.delete(key);
    try {
      const ok = await tryUpdateOnce({ payload, phoneE164 });
      if (!ok) _scheduleSeries(key, payload, phoneE164, attempt + 1);
      else console.log(`[ANTI-RACE] Actualización lograda para ${key} en intento #${attempt}`);
    } catch (e) {
      console.error("[ANTI-RACE ERROR]", e.message || e);
      _scheduleSeries(key, payload, phoneE164, attempt + 1);
    }
  }, delay);
  pendingRetries.set(key, { timer, attempt });
}

/* ================= WEBHOOK (POST) — Respuesta inmediata ================= */
app.post("/webhook", async (req, res) => {
  if (!isValidSignature(req)) return res.sendStatus(401);

  // Responder a Meta **de inmediato** para no bloquear el webhook
  res.status(200).end();

  // Procesar en background
  setImmediate(async () => {
    try {
      const entry  = req.body.entry?.[0];
      const change = entry?.changes?.[0];
      const value  = change?.value;

      const product = (value?.messaging_product || "").toLowerCase();
      if (product && product !== "whatsapp") return; // por ahora WA-only

      const waMsg = value?.messages?.[0];
      if (!waMsg) return;

      const referral  = waMsg?.referral || value?.referral || null;
      const ctwaClid  = referral?.ctwa_clid || referral?.click_id || null;
      const userPhone = waMsg?.from || null; // MSISDN
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

      // Completar con Ads si falta info (opcional)
      const needAds = !payload.ad_id || !payload.adset_id || !payload.campaign_id || !payload.campaign_name;
      if (needAds) {
        const adsExtra = await enrichFromAds({
          ad_id: payload.ad_id,
          adset_id: payload.adset_id,
          campaign_id: payload.campaign_id
        });
        for (const [k, v] of Object.entries(adsExtra)) {
          if (!payload[k]) payload[k] = v; // no sobrescribe si ya venía
        }
      }

      console.log("=== INBOUND EVENT ===", new Date().toISOString());
      console.log("platform:", payload.platform, "ctwa:", ctwaClid ? "sí" : "(no)");
      console.log("phone (raw WA):", userPhone || "(desconocido)");

      const okNow = await tryUpdateOnce({ payload, phoneE164: userPhone });
      if (okNow) {
        console.log("[OK] Lead actualizado de inmediato.");
      } else {
        const key = ctwaClid || (userPhone || "unknown");
        scheduleAntiRace(key, payload, userPhone); // 5/10/15 (y fast-probe si activaste)
      }
    } catch (e) {
      console.error("[WEBHOOK BG ERROR]", e);
    }
  });
});

/* ================= START ================= */
app.listen(process.env.PORT || 3000, () => {
  console.log("Webhook escuchando...");
});
