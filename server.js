// server.js — Meta Webhook + Kommo (write-once, sin crear leads, con enriquecimiento CTWA)

import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();

// ===== Body raw para validar firma de Meta =====
app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// ===== ENV META =====
const VERIFY_TOKEN = (process.env.META_VERIFY_TOKEN || "").trim();
const APP_SECRET   = process.env.META_APP_SECRET;

// ===== ENV KOMMO =====
const KOMMO = {
  base: (process.env.KOMMO_BASE || "").replace(/\/+$/, ""),
  clientId: process.env.KOMMO_CLIENT_ID,
  clientSecret: process.env.KOMMO_CLIENT_SECRET,
  redirectUri: process.env.KOMMO_REDIRECT_URI,
  accessToken: process.env.KOMMO_ACCESS_TOKEN || null,   // si usas token largo, déjalo aquí
  refreshToken: process.env.KOMMO_REFRESH_TOKEN || null, // si no usas refresh, puede ir vacío
};

// ===== ENV MARKETING API (resolver CTWA -> ad/adset/campaign) =====
const FB_SYS_TOKEN   = process.env.FB_SYS_TOKEN || "";        // token de usuario de sistema con ads_read/ads_management + business_management
const FB_BUSINESS_ID = process.env.FB_BUSINESS_ID || "";      // Business Manager ID (opción A)
const FB_AD_ACCOUNT  = process.env.FB_AD_ACCOUNT_ID || "";    // act_<ID> (opción B)
const FB_VER         = process.env.FB_API_VERSION || "v21.0"; // versión de Graph

// ===== Diagnóstico =====
app.get("/",  (_, res) => res.status(200).send("up"));
app.get("/health", (_, res) => res.status(200).send("ok"));

// ===== Verificación GET del webhook =====
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

// ===== Firma HMAC (POST) =====
function isValidSignature(req) {
  if (!APP_SECRET) return true; // sólo para pruebas
  const received = req.get("x-hub-signature-256") || "";
  const expected = "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  if (received.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected)); }
  catch { return false; }
}

// ===== Kommo OAuth callback (opcional) =====
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

// ===== Kommo helpers =====
async function kommoRefresh() {
  if (!KOMMO.refreshToken) return; // si no usas refresh, sal
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
      "User-Agent": "meta-webhook-kommo/1.2",
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

// ===== IDs de campos personalizados (lead) =====
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

// ===== Utilidades =====
const unix = (ts) => (ts ? Number(ts) : null);
const num  = (v) => (v == null || v === "" ? null : Number(v) || null);
const asArray = (v) => Array.isArray(v) ? v : [];
const isNonEmpty = (v) => v !== null && v !== undefined && v !== "";

// Map anti-race para reintentos diferidos (por teléfono y por clid)
const retryQueue = new Map(); // key -> timeoutId

function scheduleRetry(key, fn, attempt) {
  // 1->5min, 2->10min, 3->15min
  const delays = [0, 5, 10, 15]; // índice por attempt
  if (attempt > 3) return;

  if (retryQueue.has(key)) {
    console.log("[ANTI-RACE] Ya hay un intento programado para", key, "; omito duplicar.");
    return;
  }
  const delayMin = delays[attempt];
  const ms = delayMin * 60 * 1000;
  console.log(`[ANTI-RACE] Intento #${attempt} para ${key} en ${delayMin} min`);
  const t = setTimeout(async () => {
    retryQueue.delete(key);
    await fn(attempt);
  }, ms);
  retryQueue.set(key, t);
}

// ===== Transformadores de CFV =====
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
  const add = (id, v) => isNonEmpty(v) && out.push({ field_id: id, values: [{ value: v }] });
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
    if (isNonEmpty(have)) out[key] = have;
  };
  // Campos write-once (atribución)
  keep(FIELDS.LEAD.CTWA_CLID,      "ctwa_clid");
  keep(FIELDS.LEAD.CAMPAIGN_ID,    "campaign_id");
  keep(FIELDS.LEAD.ADSET_ID,       "adset_id");
  keep(FIELDS.LEAD.AD_ID,          "ad_id");
  keep(FIELDS.LEAD.PLATFORM,       "platform");
  keep(FIELDS.LEAD.CHANNEL_SOURCE, "channel_source");

  // Timestamps coherentes
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

// ===== Normalización de teléfono =====
function phoneCandidates(raw) {
  if (!raw) return [];
  const digits = String(raw).replace(/\D+/g, "");
  const cands = new Set();

  // variantes e164 y locales MX (+ ajusta si tu país es otro)
  cands.add(digits);                 // 5213312345678
  cands.add("+" + digits);           // +5213312345678
  cands.add("52" + digits.replace(/^52/, "")); // asegurar prefijo país MX
  cands.add("+52" + digits.replace(/^52/, ""));
  cands.add("0052" + digits.replace(/^52/, ""));
  if (digits.length >= 10) {
    const last10 = digits.slice(-10);
    cands.add(last10);               // 3312345678
  }
  return Array.from(cands);
}

// ===== Kommo: lectura/actualización =====
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
  // 1) query global
  const q = encodeURIComponent(clid);
  const res = await kommoRequest(`/api/v4/leads?query=${q}&limit=25`, { method: "GET" });
  const leads = res?._embedded?.leads || [];
  console.log("[SEARCH] leads?query=CTWA got", leads.length);
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
  // 2) primero prueba por contactos (con with=leads)
  for (const qRaw of tries) {
    const q = encodeURIComponent(qRaw);
    try {
      const res = await kommoRequest(`/api/v4/contacts?query=${q}&limit=10`, { method: "GET" });
      const contacts = res?._embedded?.contacts || [];
      console.log(`[SEARCH] contacts?query=${qRaw} -> ${contacts.length}`);
      for (const c of contacts) {
        const det = await kommoRequest(`/api/v4/contacts/${c.id}?with=leads`, { method: "GET" });
        const leads = det?._embedded?.leads || [];
        console.log(`[SEARCH] contact ${c.id} leads -> ${leads.length}`);
        if (!leads.length) continue;
        leads.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
        const latest = leads[0];
        const full = await getLeadById(latest.id);
        return full || latest;
      }
    } catch (e) {
      console.warn("Búsqueda por teléfono (contacts) falló con", qRaw, "->", e.message || e);
    }
  }

  // 3) si aún nada: prueba por leads?query=tel (algunas veces indexa primero el lead)
  for (const qRaw of tries) {
    const q = encodeURIComponent(qRaw);
    try {
      const res = await kommoRequest(`/api/v4/leads?query=${q}&limit=10`, { method: "GET" });
      const leads = res?._embedded?.leads || [];
      console.log(`[SEARCH] leads?query=${qRaw} -> ${leads.length}`);
      if (leads.length) {
        const lead = leads[0];
        console.log("[PHONE->LEADS] match lead", lead.id, "con query", qRaw);
        const full = await getLeadById(lead.id);
        return full || lead;
      }
    } catch (e) {
      console.warn("Búsqueda por teléfono (leads) falló con", qRaw, "->", e.message || e);
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

// ===== Marketing API: resolver CTWA -> IDs de anuncio (write-once) =====
async function resolveCtwaAdIds(ctwaClid) {
  if (!ctwaClid || !FB_SYS_TOKEN) {
    console.log("[CTWA RESOLVER] omitido (faltan TOKEN/CLID)");
    return null;
  }
  try {
    // Opción A: por negocio
    let url = `https://graph.facebook.com/${FB_VER}/${FB_BUSINESS_ID}/ctwa_clicks` +
      `?ctwa_click_id=${encodeURIComponent(ctwaClid)}` +
      `&fields=ad_id,adset_id,campaign_id,campaign_name,ad_name,adset_name` +
      `&access_token=${encodeURIComponent(FB_SYS_TOKEN)}`;
    let r = await fetch(url);

    // Fallback Opción B: por cuenta publicitaria
    if ((!r.ok || r.status === 400 || r.status === 404) && FB_AD_ACCOUNT) {
      url = `https://graph.facebook.com/${FB_VER}/${FB_AD_ACCOUNT}/ctwa_clicks` +
        `?ctwa_click_id=${encodeURIComponent(ctwaClid)}` +
        `&fields=ad_id,adset_id,campaign_id,campaign_name,ad_name,adset_name` +
        `&access_token=${encodeURIComponent(FB_SYS_TOKEN)}`;
      r = await fetch(url);
    }

    if (!r.ok) {
      const t = await r.text().catch(() => "");
      console.warn("[CTWA RESOLVER] fallo:", r.status, t);
      return null;
    }
    const data = await r.json();
    const item = Array.isArray(data?.data) ? data.data[0] : data;
    if (!item) return null;

    return {
      ad_id:         item.ad_id || null,
      adset_id:      item.adset_id || null,
      campaign_id:   item.campaign_id || null,
      campaign_name: item.campaign_name || null,
    };
  } catch (e) {
    console.warn("[CTWA RESOLVER] error:", e.message || e);
    return null;
  }
}

// ===== Lógica principal: actualizar si existe (no crear) =====
async function updateExistingLead({ payload, phoneE164 }) {
  let lead = null;

  // 1) por CTWA
  if (payload.ctwa_clid) {
    lead = await findLeadByCtwa(payload.ctwa_clid);
    if (lead) console.log("[MATCH] por CTWA en lead", lead.id);
  }

  // 2) por teléfono (contacts y luego leads)
  if (!lead && phoneE164) {
    lead = await findLeadByPhone(phoneE164);
    if (lead) console.log("[MATCH] por teléfono en lead", lead.id);
  }

  if (!lead) {
    console.log("[NO MATCH] Aún no existe lead/contacto en Kommo.");
    return { updated: false, leadId: null };
  }

  // Enriquecimiento write-once: si tenemos CTWA y faltan IDs, intenta completarlos
  if (payload.ctwa_clid && (!payload.campaign_id || !payload.adset_id || !payload.ad_id)) {
    const metaIds = await resolveCtwaAdIds(payload.ctwa_clid);
    if (metaIds) {
      payload.campaign_id   = payload.campaign_id || metaIds.campaign_id || null;
      payload.adset_id      = payload.adset_id    || metaIds.adset_id    || null;
      payload.ad_id         = payload.ad_id       || metaIds.ad_id       || null;
      payload.campaign_name = payload.campaign_name || metaIds.campaign_name || null;
      console.log("[CTWA RESOLVER] completado:", metaIds);
    }
  }

  const merged = mergeAttribution(lead.custom_fields_values, payload);
  await updateLeadCFV(lead.id, merged);
  return { updated: true, leadId: lead.id };
}

// ===== Webhook POST =====
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
      campaign_id:    referral?.campaign_id || null, // normalmente Meta no lo manda en WA
      adset_id:       referral?.adset_id    || null,
      ad_id:          referral?.ad_id       || null,

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
    console.log("phone (raw WA):", userPhone || "(desconocido)");

    // Intento inmediato
    const attemptOnce = async (attempt) => {
      const { updated, leadId } = await updateExistingLead({ payload, phoneE164: userPhone });
      if (updated) {
        console.log(`[ANTI-RACE] Actualización lograda para ${ctwaClid || userPhone} en intento #${attempt}`);
        return true;
      }
      return false;
    };

    const okNow = await attemptOnce(0);
    if (!okNow) {
      // Programar reintentos 5/10/15
      const keyPhone = userPhone || "";
      const keyClid  = ctwaClid   || "";

      if (keyClid) {
        scheduleRetry(keyClid, async (n) => {
          const done = await attemptOnce(n);
          if (!done && n < 3) scheduleRetry(keyClid, arguments.callee, n + 1);
        }, 1);
      }
      if (keyPhone) {
        scheduleRetry(keyPhone, async (n) => {
          const done = await attemptOnce(n);
          if (!done && n < 3) scheduleRetry(keyPhone, arguments.callee, n + 1);
        }, 1);
      }
    }

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
