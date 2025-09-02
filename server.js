// server.js — Meta Webhook + Kommo
// Atribución write-once sin crear leads, anti-race, y enriquecimiento correcto:
// 1) referral directo
// 2) referral.source_url (URL parameters con macros {ad.id}, {adset.id}, {campaign.id})
// 3) Marketing API solo si ya hay ad_id (opcional)

import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import { setTimeout as wait } from "timers/promises";

const app = express();

app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// ===== META =====
const VERIFY_TOKEN       = (process.env.META_VERIFY_TOKEN || "").trim();
const APP_SECRET         = process.env.META_APP_SECRET;
const META_ADS_TOKEN     = process.env.META_ADS_TOKEN || "";   // token de usuario de sistema con ads_read/ads_management
const META_GRAPH_VERSION = process.env.META_GRAPH_VERSION || "v20.0";
const ENABLE_AD_RESOLVER = (process.env.ENABLE_AD_RESOLVER || "1") === "1"; // 1=habilitado si hay ad_id y token

// ===== KOMMO =====
const KOMMO = {
  base: (process.env.KOMMO_BASE || "").replace(/\/+$/, ""),
  clientId: process.env.KOMMO_CLIENT_ID,
  clientSecret: process.env.KOMMO_CLIENT_SECRET,
  redirectUri: process.env.KOMMO_REDIRECT_URI,
  accessToken: process.env.KOMMO_ACCESS_TOKEN || null,
  refreshToken: process.env.KOMMO_REFRESH_TOKEN || null, // si usas token de larga duración, puede quedar vacío
};

// ===== DIAGNÓSTICO =====
app.get("/",  (_, res) => res.status(200).send("up"));
app.get("/health", (_, res) => res.status(200).send("ok"));

// ===== VERIFY (GET) =====
app.get("/webhook", (req, res) => {
  const mode = (req.query["hub.mode"] || "").trim();
  const token = (req.query["hub.verify_token"] || "").trim();
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// ===== HMAC (POST) =====
function isValidSignature(req) {
  if (!APP_SECRET) return true; // para pruebas
  const received = req.get("x-hub-signature-256") || "";
  const expected = "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  if (received.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected)); }
  catch { return false; }
}

// ===== KOMMO helpers =====
async function kommoRequest(path, options = {}) {
  const url = `${KOMMO.base}${path}`;
  const r = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${KOMMO.accessToken}`,
      "User-Agent": "meta-webhook-kommo/1.1",
      ...(options.headers || {}),
    },
  });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    console.error(`Kommo ${r.status} ${url} ::`, t);
    throw new Error(`Kommo ${r.status}: ${t}`);
  }
  try { return await r.json(); } catch { return null; }
}

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

const unix   = (ts) => (ts ? Number(ts) : null);
const num    = (v) => (v == null || v === "" ? null : Number(v) || null);
const asArr  = (v) => Array.isArray(v) ? v : [];

// ——— CFV build y merge write-once ———
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

function cfvToMap(cfv) {
  const m = new Map();
  for (const cf of asArr(cfv)) {
    const id = cf.field_id;
    const v  = cf.values?.[0]?.value;
    if (id != null) m.set(id, v);
  }
  return m;
}

function mergeAttribution(existingCFV = [], incoming) {
  const m = cfvToMap(existingCFV);
  const out = { ...incoming };
  const keep = (fid, key) => {
    const have = m.get(fid);
    if (have != null && have !== "") out[key] = have;
  };
  // write-once de atribución
  keep(FIELDS.LEAD.CTWA_CLID,      "ctwa_clid");
  keep(FIELDS.LEAD.CAMPAIGN_ID,    "campaign_id");
  keep(FIELDS.LEAD.ADSET_ID,       "adset_id");
  keep(FIELDS.LEAD.AD_ID,          "ad_id");
  keep(FIELDS.LEAD.PLATFORM,       "platform");
  keep(FIELDS.LEAD.CHANNEL_SOURCE, "channel_source");

  const firstOld = num(m.get(FIELDS.LEAD.FIRST_TS));
  const lastOld  = num(m.get(FIELDS.LEAD.LAST_TS));
  const firstNew = num(incoming.first_message_unix);
  const lastNew  = num(incoming.last_message_unix);

  out.first_message_unix = (firstOld != null && firstNew != null)
    ? Math.min(firstOld, firstNew)
    : (firstOld ?? firstNew ?? null);

  out.last_message_unix = (lastOld != null && lastNew != null)
    ? Math.max(lastOld, lastNew)
    : (lastOld ?? lastNew ?? null);

  return out;
}

// ——— Búsquedas en Kommo ———
function phoneCandidates(raw) {
  if (!raw) return [];
  const d = String(raw).replace(/\D+/g, "");
  const s = new Set([d, `+${d}`]);
  if (d.length >= 10) {
    const last10 = d.slice(-10);
    s.add(last10);
    s.add(`+52${last10}`); // ajusta prefijo a tu país si no es MX
    s.add(`0052${last10}`); // variante internacional
  }
  return Array.from(s);
}

async function getLeadById(id) {
  try { return await kommoRequest(`/api/v4/leads/${id}`, { method: "GET" }); }
  catch { return null; }
}

async function findLeadByCtwa(clid) {
  if (!clid) return null;
  const q = encodeURIComponent(clid);
  const res = await kommoRequest(`/api/v4/leads?query=${q}&limit=25`, { method: "GET" });
  const leads = res?._embedded?.leads || [];
  const hit = leads.find(l =>
    asArr(l.custom_fields_values).some(cf => cf.field_id === FIELDS.LEAD.CTWA_CLID &&
      cf.values?.[0]?.value === clid)
  );
  if (!hit) return null;
  return await getLeadById(hit.id) || hit;
}

async function findLeadByPhone(rawPhone) {
  const tries = phoneCandidates(rawPhone);
  for (const qRaw of tries) {
    const q = encodeURIComponent(qRaw);
    try {
      // 1) contacts
      const res = await kommoRequest(`/api/v4/contacts?query=${q}&limit=10`, { method: "GET" });
      const contact = res?._embedded?.contacts?.[0];
      if (contact) {
        const det = await kommoRequest(`/api/v4/contacts/${contact.id}?with=leads`, { method: "GET" });
        const leads = det?._embedded?.leads || [];
        if (leads.length) {
          leads.sort((a,b)=>(b.updated_at||0)-(a.updated_at||0));
          const full = await getLeadById(leads[0].id);
          console.log("[MATCH] por teléfono en lead", leads[0].id);
          return full || leads[0];
        }
      }
      // 2) leads?query (por si el número está pegado en nombre/nota)
      const resL = await kommoRequest(`/api/v4/leads?query=${q}&limit=5`, { method: "GET" });
      const leads2 = resL?._embedded?.leads || [];
      if (leads2.length) {
        console.log("[PHONE->LEADS] match lead", leads2[0].id, "con query", qRaw);
        const full = await getLeadById(leads2[0].id);
        return full || leads2[0];
      }
    } catch (e) {
      console.warn("findLeadByPhone error con", qRaw, "->", e.message || e);
    }
  }
  return null;
}

async function updateLeadCFV(leadId, payload) {
  const cfv = leadCFV(payload);
  const body = [{ id: leadId, custom_fields_values: cfv }];
  await kommoRequest(`/api/v4/leads`, { method: "PATCH", body: JSON.stringify(body) });
  console.log("[PATCH OK] lead", leadId);
}

// ====== Enriquecimiento correcto ======

// 2.a) Extraer IDs de querystring en referral.source_url
function parseQuery(qs) {
  const out = {};
  if (!qs) return out;
  // qs puede venir como URL completa; usamos URL para parsear seguro
  try {
    const u = new URL(qs);
    u.searchParams.forEach((v,k)=>{ out[k]=v; });
    return out;
  } catch {
    // si viene solo "a=1&b=2"
    for (const part of String(qs).replace(/^\?/, "").split("&")) {
      if (!part) continue;
      const [k,v] = part.split("=");
      out[decodeURIComponent(k)] = decodeURIComponent(v || "");
    }
    return out;
  }
}

// 3) Enriquecer vía Marketing API si YA tenemos ad_id y token
async function enrichFromAdId(ad_id) {
  if (!ENABLE_AD_RESOLVER || !META_ADS_TOKEN || !ad_id) return null;
  try {
    const url = `https://graph.facebook.com/${META_GRAPH_VERSION}/${ad_id}?fields=id,name,adset_id,campaign_id&access_token=${encodeURIComponent(META_ADS_TOKEN)}`;
    const r = await fetch(url);
    if (!r.ok) {
      const t = await r.text();
      console.warn("[AD RESOLVER] fallo:", r.status, t);
      return null;
    }
    const j = await r.json();
    return {
      ad_id: j.id || null,
      adset_id: j.adset_id || null,
      campaign_id: j.campaign_id || null,
      campaign_name: null, // podrías añadir otro fetch a campaign para name si lo necesitas
    };
  } catch (e) {
    console.warn("[AD RESOLVER] error:", e.message || e);
    return null;
  }
}

// Mezcla de todas las fuentes de Ads (orden de prioridad)
async function resolveAdsInfo(referral) {
  let ad_id = referral?.ad_id || null;
  let adset_id = referral?.adset_id || null;
  let campaign_id = referral?.campaign_id || null;

  // 2) source_url -> ?ad_id={ad.id}&adset_id={adset.id}&campaign_id={campaign.id}
  const fromUrl = parseQuery(referral?.source_url || "");
  ad_id       = ad_id       || fromUrl.ad_id       || null;
  adset_id    = adset_id    || fromUrl.adset_id    || null;
  campaign_id = campaign_id || fromUrl.campaign_id || null;

  // 3) Marketing API si ya hay ad_id
  if (!campaign_id || !adset_id) {
    const extra = await enrichFromAdId(ad_id);
    if (extra) {
      ad_id       = ad_id       || extra.ad_id;
      adset_id    = adset_id    || extra.adset_id;
      campaign_id = campaign_id || extra.campaign_id;
    }
  }

  return { ad_id, adset_id, campaign_id };
}

// ====== Anti-race (reintentos) ======
const pendingKeys = new Map(); // key -> {attempts, max, delayMs}
function scheduleRetry(key, fn, { max=3, delayMs=5*60*1000 } = {}) {
  const cur = pendingKeys.get(key);
  if (cur && cur.attempts >= max) return;
  if (cur) {
    cur.attempts += 1;
    pendingKeys.set(key, cur);
  } else {
    pendingKeys.set(key, { attempts: 1, max, delayMs });
  }
  const attempt = pendingKeys.get(key).attempts;
  console.log(`[ANTI-RACE] Intento #${attempt} para ${key} en ${Math.round(delayMs/60000)} min`);
  (async () => {
    await wait(delayMs);
    try { await fn(); }
    finally {
      // si fn hizo update, normalmente logueará y puedes limpiar la key
      // aquí no limpiamos automáticamente para conservar conteo
    }
  })();
}

// ====== Actualización “solo si existe” ======
async function updateExistingLead({ payload, phoneE164 }) {
  let lead = null;

  if (payload.ctwa_clid) {
    lead = await findLeadByCtwa(payload.ctwa_clid);
    if (lead) console.log("[MATCH] por CTWA en lead", lead.id);
  }
  if (!lead && phoneE164) {
    lead = await findLeadByPhone(phoneE164);
  }

  if (!lead) {
    console.log("[NO MATCH] Aún no existe lead/contacto en Kommo.");
    return { updated: false, leadId: null };
  }

  const merged = mergeAttribution(lead.custom_fields_values, payload);
  await updateLeadCFV(lead.id, merged);
  return { updated: true, leadId: lead.id };
}

// ====== WEBHOOK (POST) ======
app.post("/webhook", async (req, res) => {
  if (!isValidSignature(req)) return res.sendStatus(401);

  try {
    const entry  = req.body.entry?.[0];
    const change = entry?.changes?.[0];
    const value  = change?.value;

    const product = (value?.messaging_product || "").toLowerCase();
    if (product && product !== "whatsapp") {
      return res.sendStatus(200);
    }

    const waMsg = value?.messages?.[0];
    if (!waMsg) {
      console.log("Sin messages[0]; nada que hacer.");
      return res.sendStatus(200);
    }

    const referral = waMsg?.referral || value?.referral || null;
    const ctwaClid = referral?.ctwa_clid || referral?.click_id || null;
    const userPhone = waMsg?.from || null;
    const ts = unix(waMsg?.timestamp);
    const platform = "whatsapp";

    // Resolver anuncios correctamente
    const ads = await resolveAdsInfo(referral);

    const payload = {
      platform,
      channel_source: referral ? "ctwa" : platform,
      ctwa_clid:      ctwaClid,
      campaign_id:    ads.campaign_id || null,
      adset_id:       ads.adset_id    || null,
      ad_id:          ads.ad_id       || null,
      first_message_unix: ts,
      last_message_unix:  ts,
      thread_id:      waMsg?.id || null,
      entry_owner_id: entry?.id || null,
      // opcionales
      campaign_name:     null,
      media_budget_hint: null,
      deal_amount:       null,
    };

    console.log("=== INBOUND EVENT ===", new Date().toISOString());
    console.log("platform:", payload.platform, "ctwa:", ctwaClid ? "sí" : "(no)");
    console.log("phone (raw):", userPhone || "(desconocido)");

    // Actualizar si existe
    const act = async () => {
      const { updated, leadId } = await updateExistingLead({ payload, phoneE164: userPhone });
      if (updated) {
        console.log("[OK] Lead actualizado:", leadId);
        // si se logró actualizar, puedes limpiar la llave de pendingKeys
        if (ctwaClid && pendingKeys.has(ctwaClid)) pendingKeys.delete(ctwaClid);
        if (userPhone && pendingKeys.has(userPhone)) pendingKeys.delete(userPhone);
      } else {
        // programar reintento (5, 10, 15 min – 3 intentos)
        const key = ctwaClid || userPhone || `evt:${waMsg?.id}`;
        const attempts = pendingKeys.get(key)?.attempts || 0;
        if (attempts === 0) scheduleRetry(key, act, { max: 3, delayMs: 5*60*1000 });
        else if (attempts === 1) scheduleRetry(key, act, { max: 3, delayMs: 10*60*1000 });
        else if (attempts === 2) scheduleRetry(key, act, { max: 3, delayMs: 15*60*1000 });
      }
    };

    await act();
    return res.sendStatus(200);
  } catch (e) {
    console.error("[WEBHOOK ERROR]", e);
    return res.sendStatus(500);
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Webhook escuchando...");
});
