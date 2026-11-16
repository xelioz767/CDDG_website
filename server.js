import "dotenv/config";
import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const { PORT = 3000, ALLOWED_ORIGIN = "*", ADMIN_PASSWORD, TOKEN_SECRET, DISCORD_WEBHOOK_URL,
  BATTLEMETRICS_ID, WHITELIST_FEED_KEY, MIN_WORDS = 100 } = process.env;
if (!ADMIN_PASSWORD || !TOKEN_SECRET) { console.error("Set ADMIN_PASSWORD and TOKEN_SECRET in .env"); process.exit(1); }

const DB = path.join(process.cwd(), "data", "applications.json");
await fs.mkdir(path.dirname(DB), { recursive: true });
let queue = Promise.resolve();
const read = async () => { try { return JSON.parse(await fs.readFile(DB, "utf8")); } catch { return []; } };
// serialise writes so two requests can't overwrite each other
const mutate = fn => (queue = queue.then(async () => { const d = await read(); const out = await fn(d); await fs.writeFile(DB, JSON.stringify(d, null, 2)); return out; }));

const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: ALLOWED_ORIGIN === "*" ? true : ALLOWED_ORIGIN.split(",") }));
app.use(express.json({ limit: "50kb" }));
const limit = (windowMin, max) => rateLimit({ windowMs: windowMin * 60000, max, standardHeaders: true, legacyHeaders: false, message: { error: "Too many requests. Try again later." } });

const clean = (v, n) => String(v ?? "").trim().slice(0, n);
const words = s => (s.match(/\S+/g) || []).length;
async function hook(embed) {
  if (!DISCORD_WEBHOOK_URL) return;
  try { await fetch(DISCORD_WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "Whitelist", embeds: [embed] }) }); }
  catch (e) { console.error("Webhook failed:", e.message); }
}
const field = (name, value, inline = true) => ({ name, value: String(value || "n/a").slice(0, 1000), inline });

// ---- public: submit application ----
app.post("/api/apply", limit(60, 5), async (req, res) => {
  const b = req.body || {};
  if (b.website) return res.json({ id: "ok" }); // honeypot
  const a = { discord: clean(b.discord, 40), age: parseInt(b.age, 10), steamId: clean(b.steamId, 17), char: clean(b.char, 60),
    exp: clean(b.exp, 40), story: clean(b.story, 6000), why: clean(b.why, 2000) };
  if (a.discord.length < 2) return res.status(400).json({ error: "Enter your Discord username." });
  if (!(a.age >= 1 && a.age <= 99)) return res.status(400).json({ error: "Enter a valid age." });
  if (!/^7656\d{13}$/.test(a.steamId)) return res.status(400).json({ error: "Enter a valid SteamID64." });
  if (a.char.length < 2) return res.status(400).json({ error: "Enter your character's name." });
  if (!a.exp) return res.status(400).json({ error: "Choose your experience level." });
  if (words(a.story) < Number(MIN_WORDS)) return res.status(400).json({ error: `Backstory needs at least ${MIN_WORDS} words.` });
  if (b.rules !== "on" && b.rules !== true) return res.status(400).json({ error: "You must agree to the rules." });

  const result = await mutate(d => {
    const dup = d.find(x => (x.steamId === a.steamId || x.discord.toLowerCase() === a.discord.toLowerCase()) && x.status !== "denied");
    if (dup) return { error: dup.status === "approved" ? "You're already whitelisted." : "You already have a pending application." };
    const rec = { id: crypto.randomUUID(), ...a, status: "pending", note: "", created: new Date().toISOString() };
    d.push(rec); return { rec };
  });
  if (result.error) return res.status(409).json({ error: result.error });
  const r = result.rec;
  hook({ title: "New whitelist application", color: 0xc9a24a, fields: [field("Discord", r.discord), field("Age", r.age), field("SteamID64", r.steamId),
    field("Character", r.char), field("RP experience", r.exp), field("Backstory", r.story, false), field("Application ID", r.id, false)] });
  res.json({ id: r.id });
});

// ---- public: check status by ID ----
app.get("/api/apply/:id", limit(15, 30), async (req, res) => {
  const r = (await read()).find(x => x.id === req.params.id);
  if (!r) return res.status(404).json({ error: "No application found with that ID." });
  res.json({ status: r.status, note: r.status === "pending" ? "" : r.note });
});

// ---- public: live server status (BattleMetrics, cached) ----
let cache = { t: 0, v: null };
app.get("/api/status", limit(1, 60), async (_req, res) => {
  if (!BATTLEMETRICS_ID) return res.json({ online: false });
  if (Date.now() - cache.t > 30000) {
    try {
      const j = await (await fetch(`https://api.battlemetrics.com/servers/${encodeURIComponent(BATTLEMETRICS_ID)}`)).json();
      const s = j.data.attributes;
      cache = { t: Date.now(), v: { online: s.status === "online", players: s.players, maxPlayers: s.maxPlayers, map: s.details?.map } };
    } catch { cache = { t: Date.now(), v: { online: false } }; }
  }
  res.json(cache.v);
});

// ---- admin auth (HMAC-signed, 12h tokens) ----
const sign = s => crypto.createHmac("sha256", TOKEN_SECRET).update(s).digest("base64url");
const sha = s => crypto.createHash("sha256").update(s).digest();
app.post("/api/admin/login", limit(15, 8), (req, res) => {
  const ok = crypto.timingSafeEqual(sha(String(req.body?.password ?? "")), sha(ADMIN_PASSWORD));
  if (!ok) return res.status(401).json({ error: "Wrong password." });
  const exp = String(Date.now() + 12 * 3600e3);
  res.json({ token: exp + "." + sign(exp) });
});
function auth(req, res, next) {
  const [exp, sig] = (req.headers.authorization || "").replace("Bearer ", "").split(".");
  if (!exp || !sig || sig.length !== sign(exp).length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(exp))) || Date.now() > Number(exp))
    return res.status(401).json({ error: "Unauthorized" });
  next();
}
app.get("/api/admin/applications", auth, async (_req, res) => res.json({ applications: (await read()).reverse() }));
app.post("/api/admin/applications/:id", auth, async (req, res) => {
  const status = req.body?.status, note = clean(req.body?.note, 300);
  if (!["approved", "denied", "pending"].includes(status)) return res.status(400).json({ error: "Invalid status." });
  const r = await mutate(d => { const x = d.find(y => y.id === req.params.id); if (x) { x.status = status; x.note = note; x.decided = new Date().toISOString(); } return x; });
  if (!r) return res.status(404).json({ error: "Not found." });
  hook({ title: `Application ${status}`, color: status === "approved" ? 0x9bbd84 : 0xe0775a, fields: [field("Discord", r.discord), field("Character", r.char), field("SteamID64", r.steamId), field("Note", r.note, false)] });
  res.json({ ok: true });
});

// ---- approved SteamID64 list for the DayZ server (whitelist.txt) ----
app.get("/api/whitelist.txt", async (req, res) => {
  if (!WHITELIST_FEED_KEY || req.query.key !== WHITELIST_FEED_KEY) return res.status(401).type("text").send("Unauthorized");
  res.type("text").send((await read()).filter(x => x.status === "approved").map(x => x.steamId).join("\n") + "\n");
});

app.get("/", (_req, res) => res.json({ ok: true }));
app.listen(PORT, () => console.log("Whitelist API listening on", PORT));
