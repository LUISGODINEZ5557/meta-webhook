import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();

// Body crudo para validar firma HMAC
app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// Variables de entorno (se ponen en Render)
const VERIFY_TOKEN = process.env.META_VERIFY_TOKEN; // inventa uno
const APP_SECRET   = process.env.META_APP_SECRET;   // de tu App Meta

// 1) Verificación de Meta (GET)
app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// 2) Validación de firma HMAC (X-Hub-Signature-256)
function isValidSignature(req) {
  const received = req.get("x-hub-signature-256") || "";
  const expected = "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  if (received.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected)); }
  catch { return false; }
}

// 3) Recepción de eventos (POST)
app.post("/webhook", (req, res) => {
  if (!isValidSignature(req)) return res.sendStatus(401);

  const entry  = req.body.entry?.[0];
  const change = entry?.changes?.[0];
  const value  = change?.value;

  // WhatsApp: referral trae el Click ID de CTWA cuando aplica
  const waMsg    = value?.messages?.[0];
  const referral = waMsg?.referral || value?.referral;
  const ctwaClid = referral?.ctwa_clid || referral?.click_id || null;

  console.log("INBOUND EVENT:", JSON.stringify(req.body, null, 2));
  console.log("CTWA_CLICK_ID:", ctwaClid);

  return res.sendStatus(200);
});

// Healthcheck para Render
app.get("/health", (_, res) => res.status(200).send("ok"));

app.listen(process.env.PORT || 3000, () => {
  console.log("Webhook escuchando...");
});
