import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();

app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

const VERIFY_TOKEN = process.env.META_VERIFY_TOKEN;
const APP_SECRET   = process.env.META_APP_SECRET;

// Diagnóstico
app.get("/", (_, res) => res.status(200).send("up"));
app.get("/health", (_, res) => res.status(200).send("ok"));

// 1) Verificación (GET) con tolerancia a espacios
app.get("/webhook", (req, res) => {
  const mode = (req.query["hub.mode"] || "").trim();
  const token = (req.query["hub.verify_token"] || "").trim();
  const challenge = req.query["hub.challenge"];
  const EXPECTED = (VERIFY_TOKEN || "").trim();

  console.log("VERIFY_TOKEN set?:", !!EXPECTED, "len:", EXPECTED.length);
  console.log("Incoming token prefix/suffix:", token.slice(0,4), "...", token.slice(-4));

  if (mode === "subscribe" && token && token === EXPECTED) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// 2) Firma HMAC (POST)
function isValidSignature(req) {
  const received = req.get("x-hub-signature-256") || "";
  const expected = "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  if (received.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected)); }
  catch { return false; }
}

// 3) Eventos (POST)
app.post("/webhook", (req, res) => {
  if (!isValidSignature(req)) return res.sendStatus(401);

  const entry  = req.body.entry?.[0];
  const change = entry?.changes?.[0];
  const value  = change?.value;

  const waMsg    = value?.messages?.[0];
  const referral = waMsg?.referral || value?.referral;
  const ctwaClid = referral?.ctwa_clid || referral?.click_id || null;

  console.log("INBOUND EVENT:", JSON.stringify(req.body, null, 2));
  console.log("CTWA_CLICK_ID:", ctwaClid);

  return res.sendStatus(200);
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Webhook escuchando...");
});
