// server.js — Meta Webhook + Kommo (WA con token invisible)
// - SmartLink /go/wa sin #ATTR visible: usa token invisible (zero-width) para unir clic→mensaje
// - Cache de clics con TTL
// - Catálogo de tecnologías/modelos y texto dinámico con fallback
// - Atribución write-once en Kommo (no crea leads; solo actualiza si existe)
// - Anti-race: reintentos 5/10/15 min si Kommo aún no tiene el lead
// - Enriquecimiento: referral + source_url (?ad_id, etc) + (opcional) Marketing API por ad_id

import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import { setTimeout as wait } from "timers/promises";

const app = express();

// ===== Body crudo para firma HMAC =====
app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// ===== ENV (Meta) =====
const VERIFY_TOKEN       = (process.env.META_VERIFY_TOKEN || "").trim();
const APP_SECRET         = process.env.META_APP_SECRET;
const META_ADS_TOKEN     = process.env.META_ADS_TOKEN || "";   // token de usuario de sistema con ads_read/ads_management
const META_GRAPH_VERSION = process.env.META_GRAPH_VERSION || "v20.0";
const ENABLE_AD_RESOLVER = (process.env.ENABLE_AD_RESOLVER || "1") === "1"; // si hay ad_id+token

// ===== ENV (SmartLink defaults) =====
const WA_DEFAULT_PHONE   = (process.env.WA_DEFAULT_PHONE || "").replace(/\D+/g, ""); // ej. 5213334949317

// ===== ENV (Kommo) =====
const KOMMO = {
  base: (process.env.KOMMO_BASE || "").replace(/\/+$/, ""),
  accessToken: process.env.KOMMO_ACCESS_TOKEN || null, // larga duración OK
};

// ===== Campos Kommo (IDs que nos diste) =====
const FIELDS = {
  LEAD: {
    CTWA_CLID:          2097583,
    CAMPAIGN_ID:        2097585,
    ADSET_ID:           2097587,
    AD_ID:              2097589,
    PLATFORM:           2097591,   // "whatsapp"
    CHANNEL_SOURCE:     2097593,   // "ctwa" o "whatsapp"
    FIRST_TS:           2097597,
    LAST_TS:            2097599,
    THREAD_ID:          2097601,
    ENTRY_OWNER_ID:     2097603,
    CAMPAIGN_NAME:      2097605,
    MEDIA_BUDGET_HINT:  2097607,
    DEAL_AMOUNT:        2097609,

    // Nuevos:
    TECH:               2097641,   // Tecnología
    MODEL:              2097643,   // Modelo
    SITE_SOURCE:        2097645,   // Plataforma del anuncio (fb/ig/msg/wa/an)
    PLACEMENT:          2097647,   // Ubicación (feed/story/reels/…)
  }
};

// ===== Diagnóstico =====
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

// ===== Firma HMAC (POST) =====
function isValidSignature(req) {
  if (!APP_SECRET) return true; // para pruebas
  const received = req.get("x-hub-signature-256") || "";
  const expected = "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  if (received.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected)); }
  catch { return false; }
}

// ===== Utilidades generales =====
const unix   = (ts) => (ts ? Number(ts) : null);
const num    = (v) => (v == null || v === "" ? null : Number(v) || null);
const asArr  = (v) => Array.isArray(v) ? v : [];
const enc    = encodeURIComponent;

// ====== Catálogo tecnología/modelos ======
const CATALOG = {
  depilacion: {
    label: "Depilación",
    models: {
      "stimmung 2": "STIMMUNG 2",
      "stimmung 2 mini": "STIMMUNG 2 MINI",
      "stimmung 3": "STIMMUNG 3",
      "stimmung 3 dual": "STIMMUNG 3 DUAL",
      "stimmung 3 mini": "STIMMUNG 3 MINI",
      "stimmung 4": "STIMMUNG 4",
      "stimmung max": "STIMMUNG MAX",
      "stimmung yag": "STIMMUNG YAG",
      "stimmung 4 dual": "STIMMUNG 4 DUAL",
    }
  },
  reductivos: {
    label: "Reductivos",
    models: {
      "steiger max": "STEIGER MAX",
      "steiger max mini": "STEIGER MAX MINI",
      "sonnen max": "SONNEN MAX",
      "ice pro": "ICE PRO",
      "indeed": "INDEED",
    }
  },
  rejuvenecimiento: {
    label: "Rejuvenecimiento",
    models: {
      "frack mini": "FRACK MINI",
      "frack max": "FRACK MAX",
      "hifu": "HIFU",
      "heilung": "HEILUNG",
    }
  },
  "eliminacion de pigmentos": {
    label: "Eliminación de Pigmentos",
    models: {
      "mond max": "MOND MAX",
      "bleisten max": "BLEISTEN MAX",
    }
  },
  "cuidados de la piel": {
    label: "Cuidados de la piel",
    models: {
      "hidrofacial 9 en 1": "HIDROFACIAL 9 EN 1",
      "lyzer pro": "LYZER PRO",
    }
  },
  "laser para venas": {
    label: "Láser para venas",
    models: {
      "laser vascular": "Laser vascular",
    }
  },
};

// normalizadores
function norm(s) { return String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g,"").trim(); }
function toTechKey(input) {
  const n = norm(input);
  if (!n) return null;
  for (const key of Object.keys(CATALOG)) {
    if (norm(key) === n) return key;
    if (n.startsWith(norm(key))) return key;
  }
  return null;
}
function toModelKey(input) {
  const n = norm(input);
  if (!n) return null;
  for (const [tech, obj] of Object.entries(CATALOG)) {
    for (const k of Object.keys(obj.models)) {
      if (norm(k) === n) return { tech, modelKey: k };
    }
  }
  return null;
}
function pickLabel(techKey, modelKeyOrObj) {
  const fallback = "Me interesa mas informacion sobre aparatologia estetica de gama alta";
  if (!techKey) return { text: fallback, techLabel: null, modelLabel: null };
  const t = CATALOG[techKey];
  if (!t) return { text: fallback, techLabel: null, modelLabel: null };
  let modelLabel = null;
  if (modelKeyOrObj) {
    const mk = typeof modelKeyOrObj === "string" ? modelKeyOrObj : modelKeyOrObj.modelKey;
    modelLabel = t.models[mk] || null;
  }
  const text = modelLabel
    ? `Hola, me interesa mas informacion del equipo de ${t.label} ${modelLabel}.`
    : `Hola, me interesa mas informacion en ${t.label}.`;
  return { text, techLabel: t.label, modelLabel };
}

// ===== Click Cache (token invisible) =====
const CLICK_CACHE_TTL_MS = Number(process.env.CLICK_CACHE_TTL_MS || 2 * 60 * 60 * 1000); // 2h
const CLICK_CACHE = new Map(); // token -> { payload, expiresAt }
function cachePut(payload) {
  const token = (Date.now().toString(36) + Math.random().toString(36).slice(2, 8)).toUpperCase();
  CLICK_CACHE.set(token, { payload, expiresAt: Date.now() + CLICK_CACHE_TTL_MS });
  return token;
}
function cacheGet(token) {
  const it = CLICK_CACHE.get(String(token || "").toUpperCase());
  if (!it) return null;
  if (Date.now() > it.expiresAt) { CLICK_CACHE.delete(token); return null; }
  return it.payload;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of CLICK_CACHE.entries()) if (now > v.expiresAt) CLICK_CACHE.delete(k);
}, 15 * 60 * 1000);

// ===== Token invisible (zero-width) =====
const ZW_START = "\u200D"; // ZERO WIDTH JOINER
const ZW_END   = "\u2060"; // WORD JOINER
const ZW0 = "\u200B";      // ZERO WIDTH SPACE        -> bit 0
const ZW1 = "\u200C";      // ZERO WIDTH NON-JOINER   -> bit 1
function tokenToBits(tok) {
  const bits = [];
  for (const ch of String(tok)) {
    const code = ch.charCodeAt(0) & 0x7F;
    for (let i = 6; i >= 0; i--) bits.push((code >> i) & 1);
  }
  return bits;
}
function bitsToToken(bits) {
  const out = [];
  for (let i = 0; i < bits.length; i += 7) {
    const chunk = bits.slice(i, i + 7);
    if (chunk.length < 7) break;
    let code = 0;
    for (let b of chunk) code = (code << 1) | (b & 1);
    out.push(String.fromCharCode(code));
  }
  return out.join("");
}
function hideTokenInText(text, token) {
  const bits = tokenToBits(token).map(b => (b ? ZW1 : ZW0)).join("");
  return text + ZW_START + bits + ZW_END; // invisible
}
function extractHiddenToken(text) {
  const i = text.indexOf(ZW_START);
  const j = text.indexOf(ZW_END, i + 1);
  if (i === -1 || j === -1) return null;
  const payload = text.slice(i + ZW_START.length, j);
  const bits = [];
  for (const ch of payload) {
    if      (ch === ZW0) bits.push(0);
    else if (ch === ZW1) bits.push(1);
  }
  const tok = bitsToToken(bits);
  return tok || null;
}

// ===== SmartLink helpers =====
function buildAttrPayload(q) {
  const techKey =
    toTechKey(q.tech) || (toModelKey(q.model || "")?.tech ?? null);
  const modelKeyObj = toModelKey(q.model || "");
  const modelKey = modelKeyObj ? modelKeyObj.modelKey : null;

  return {
    ad_id:       q.ad_id       || null,
    adset_id:    q.adset_id    || null,
    campaign_id: q.campaign_id || null,
    site_source: q.site_source || null,  // fb/ig/msg/wa/an
    placement:   q.placement   || null,  // feed/story/reels/…
    tech:        techKey || null,
    model:       modelKey || null,
    src:         q.src || "ctwa"
  };
}
function buildWaTextFromTechModel(q) {
  const techKey =
    toTechKey(q.tech) || (toModelKey(q.model || "")?.tech ?? null);
  const modelKeyObj = toModelKey(q.model || "");
  const desc = pickLabel(techKey, modelKeyObj ? modelKeyObj.modelKey : null);
  return q.text ? String(q.text) : desc.text;
}

// ===== /go/wa: genera mensaje limpio y token invisible =====
app.get("/go/wa", (req, res) => {
  try {
    const phone = (req.query.phone || WA_DEFAULT_PHONE || "").replace(/\D+/g, "");
    if (!phone) return res.status(400).send("Falta phone (WA_DEFAULT_PHONE o ?phone=)");

    // 1) Texto limpio según tech/model (con fallback)
    let text = buildWaTextFromTechModel(req.query);

    // 2) Cachear atribución del clic y obtener token
    const attr = buildAttrPayload(req.query);
    const token = cachePut(attr);

    // 3) Insertar token INVISIBLE en el texto
    text = hideTokenInText(text, token);

    const url = `https://wa.me/${phone}?text=${enc(text)}`;
    return res.redirect(302, url);
  } catch (e) {
    console.error("Smartlink /go/wa error:", e);
    return res.status(500).send("Error");
  }
});

// ===== Kommo client =====
async function kommoRequest(path, options = {}) {
  const url = `${KOMMO.base}${path}`;
  const r = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${KOMMO.accessToken}`,
      "User-Agent": "meta-webhook-kommo/1.2",
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

// ===== CFV build / merge write-once =====
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
  // nuevos:
  add(FIELDS.LEAD.TECH,               p.tech);
  add(FIELDS.LEAD.MODEL,              p.model);
  add(FIELDS.LEAD.SITE_SOURCE,        p.site_source);
  add(FIELDS.LEAD.PLACEMENT,          p.placement);
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
  // write-once core
  keep(FIELDS.LEAD.CTWA_CLID,      "ctwa_clid");
  keep(FIELDS.LEAD.CAMPAIGN_ID,    "campaign_id");
  keep(FIELDS.LEAD.ADSET_ID,       "adset_id");
  keep(FIELDS.LEAD.AD_ID,          "ad_id");
  keep(FIELDS.LEAD.PLATFORM,       "platform");
  keep(FIELDS.LEAD.CHANNEL_SOURCE, "channel_source");
  // write-once de enriquecimiento manual
  keep(FIELDS.LEAD.TECH,           "tech");
  keep(FIELDS.LEAD.MODEL,          "model");
  keep(FIELDS.LEAD.SITE_SOURCE,    "site_source");
  keep(FIELDS.LEAD.PLACEMENT,      "placement");

  // fechas coherentes
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

// ===== Búsquedas en Kommo =====
function phoneCandidates(raw) {
  if (!raw) return [];
  const d = String(raw).replace(/\D+/g, "");
  const s = new Set([d, `+${d}`]);
  if (d.length >= 10) {
    const last10 = d.slice(-10);
    s.add(last10);
    s.add(`+52${last10}`);  // ajusta si tu país no es MX
    s.add(`0052${last10}`);
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
      // 2) leads?query (por si el número está en nombre/nota)
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

// ===== Enriquecimiento de Ads =====
function parseQuery(qs) {
  const out = {};
  if (!qs) return out;
  try {
    const u = new URL(qs);
    u.searchParams.forEach((v,k)=>{ out[k]=v; });
    return out;
  } catch {
    for (const part of String(qs).replace(/^\?/, "").split("&")) {
      if (!part) continue;
      const [k,v] = part.split("=");
      out[decodeURIComponent(k)] = decodeURIComponent(v || "");
    }
    return out;
  }
}
async function enrichFromAdId(ad_id) {
  if (!ENABLE_AD_RESOLVER || !META_ADS_TOKEN || !ad_id) return null;
  try {
    const url = `https://graph.facebook.com/${META_GRAPH_VERSION}/${ad_id}?fields=id,name,adset_id,campaign_id&access_token=${enc(META_ADS_TOKEN)}`;
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
      campaign_name: null,
    };
  } catch (e) {
    console.warn("[AD RESOLVER] error:", e.message || e);
    return null;
  }
}
async function resolveAdsInfo(referral) {
  let ad_id = referral?.ad_id || null;
  let adset_id = referral?.adset_id || null;
  let campaign_id = referral?.campaign_id || null;

  const fromUrl = parseQuery(referral?.source_url || "");
  ad_id       = ad_id       || fromUrl.ad_id       || null;
  adset_id    = adset_id    || fromUrl.adset_id    || null;
  campaign_id = campaign_id || fromUrl.campaign_id || null;

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

// Compatibilidad: parsear #ATTR si alguna vez aparece
function parseAttrTagFromText(text) {
  const m = /#ATTR\s+(.+)/i.exec(String(text || ""));
  if (!m) return {};
  const parts = m[1].trim().split(/\s+/);
  const out = {};
  for (const p of parts) {
    const [k,v] = p.split("=");
    if (k && v) out[k.trim()] = v.trim();
  }
  // normaliza claves esperadas
  return {
    ad_id: out.ad_id || null,
    adset_id: out.adset_id || null,
    campaign_id: out.campaign_id || null,
    site_source: out.site_source || null,
    placement: out.placement || null,
    tech: out.tech || null,
    model: out.model || null,
  };
}

// ===== Anti-race (reintentos) =====
const pendingKeys = new Map(); // key -> {attempts}
function scheduleRetry(key, fn, delayMs) {
  const cur = pendingKeys.get(key) || { attempts: 0 };
  if (cur.attempts >= 3) return;
  cur.attempts += 1;
  pendingKeys.set(key, cur);
  console.log(`[ANTI-RACE] Intento #${cur.attempts} para ${key} en ${Math.round(delayMs/60000)} min`);
  (async () => {
    await wait(delayMs);
    try { await fn(); } finally {}
  })();
}

// ===== Actualización solo si existe lead =====
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

// ===== WEBHOOK (POST) =====
app.post("/webhook", async (req, res) => {
  if (!isValidSignature(req)) return res.sendStatus(401);

  try {
    const entry  = req.body.entry?.[0];
    const change = entry?.changes?.[0];
    const value  = change?.value;

    const product = (value?.messaging_product || "").toLowerCase();
    if (product && product !== "whatsapp") {
      // Este archivo maneja WA; para M/IG usarías su flujo con ?ref
      return res.sendStatus(200);
    }

    const waMsg = value?.messages?.[0];
    if (!waMsg) {
      console.log("Sin messages[0]; nada que hacer.");
      return res.sendStatus(200);
    }

    const referral   = waMsg?.referral || value?.referral || null;
    const ctwaClid   = referral?.ctwa_clid || referral?.click_id || null;
    const userPhone  = waMsg?.from || null;
    const ts         = unix(waMsg?.timestamp);
    const textBody   = waMsg?.text?.body || "";

    // 1) Token invisible en el texto
    let tokenPayload = null;
    const hiddenTok = extractHiddenToken(textBody);
    if (hiddenTok) {
      tokenPayload = cacheGet(hiddenTok);
      if (tokenPayload) console.log("[TOKEN-ZW] Atribución desde cache:", tokenPayload);
      else console.warn("[TOKEN-ZW] Token no encontrado/expirado:", hiddenTok);
    } else {
      // 2) Compatibilidad (#K visible) — por si lo usaste antes
      const mTok = textBody.match(/#K\s+([A-Z0-9]+)/i);
      if (mTok?.[1]) {
        tokenPayload = cacheGet(mTok[1]);
        if (tokenPayload) console.log("[TOKEN] Atribución desde cache:", tokenPayload);
      }
    }

    // 3) Info de Ads por referral/source_url/API
    const ads = await resolveAdsInfo(referral);

    // 4) Compatibilidad: #ATTR si existiera
    const fromTag = parseAttrTagFromText(textBody);

    // 5) Mezcla de prioridad: token > #ATTR > ads
    const ad_id       = tokenPayload?.ad_id       ?? fromTag.ad_id       ?? ads.ad_id       ?? null;
    const adset_id    = tokenPayload?.adset_id    ?? fromTag.adset_id    ?? ads.adset_id    ?? null;
    const campaign_id = tokenPayload?.campaign_id ?? fromTag.campaign_id ?? ads.campaign_id ?? null;
    const site_source = tokenPayload?.site_source ?? fromTag.site_source ?? null;
    const placement   = tokenPayload?.placement   ?? fromTag.placement   ?? null;
    const techKey     = tokenPayload?.tech        ?? fromTag.tech        ?? null;
    const modelKey    = tokenPayload?.model       ?? fromTag.model       ?? null;

    const payload = {
      platform: "whatsapp",
      channel_source: referral ? "ctwa" : "whatsapp",
      ctwa_clid: ctwaClid,
      campaign_id,
      adset_id,
      ad_id,

      // enriquecimiento write-once
      site_source,
      placement,
      tech:  techKey,
      model: modelKey,

      // tiempos
      first_message_unix: ts,
      last_message_unix:  ts,

      // meta
      thread_id:      waMsg?.id || null,
      entry_owner_id: entry?.id || null,

      campaign_name:     null,
      media_budget_hint: null,
      deal_amount:       null,
    };

    console.log("=== INBOUND EVENT ===", new Date().toISOString());
    console.log("phone:", userPhone || "(?)", "ctwa:", ctwaClid ? "sí" : "(no)");

    // Intento inmediato; si no existe aún el lead, programa reintentos 5/10/15 min
    const act = async () => {
      const { updated, leadId } = await updateExistingLead({ payload, phoneE164: userPhone });
      if (updated) {
        console.log("[OK] Lead actualizado:", leadId);
        if (ctwaClid && pendingKeys.has(ctwaClid)) pendingKeys.delete(ctwaClid);
        if (userPhone && pendingKeys.has(userPhone)) pendingKeys.delete(userPhone);
      } else {
        const key = ctwaClid || userPhone || `evt:${waMsg?.id}`;
        const attempts = (pendingKeys.get(key)?.attempts) || 0;
        if (attempts === 0) scheduleRetry(key, act, 5 * 60 * 1000);
        else if (attempts === 1) scheduleRetry(key, act, 10 * 60 * 1000);
        else if (attempts === 2) scheduleRetry(key, act, 15 * 60 * 1000);
      }
    };

    await act();
    return res.sendStatus(200);
  } catch (e) {
    console.error("[WEBHOOK ERROR]", e);
    return res.sendStatus(500);
  }
});

// ===== Start =====
app.listen(process.env.PORT || 3000, () => {
  console.log("Webhook escuchando...");
});
