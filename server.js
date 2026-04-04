const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const server = http.createServer(app);

// ════════════════════════════════════════════════════
// CONFIG
// ════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const SUPABASE_URL = process.env.SUPABASE_URL || "https://ohmkqlouiepzkbyztnsm.supabase.co";
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9obWtxbG91aWVwemtieXp0bnNtIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2OTI2ODYyMywiZXhwIjoyMDg0ODQ0NjIzfQ.Z3BNfmfoWAO1ocgCJBadxfKF_X54fF9KZQfVn0woDes";
const SEEKNOW_API_KEY = process.env.SEEKNOW_API_KEY || "seek-8dc2aedb7cf07a0faf0a0fae7e27a869ff9536e19ea676ef";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "https://rapace.pages.dev,https://www.rapace.pages.dev").split(",").map(s => s.trim());

const ADMIN_IDS = new Set(["5a819614-acac-4c54-a529-d15da447a47a", "d834eeb8-7eb5-4c61-a46e-e3c6d7fcadae"]);

console.log("[INIT] Starting Rapace Backend v2.0");
console.log("[INIT] CORS origins:", ALLOWED_ORIGINS);

// ════════════════════════════════════════════════════
// SUPABASE
// ════════════════════════════════════════════════════
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } });

// ════════════════════════════════════════════════════
// SECURITY
// ════════════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.disable("x-powered-by");
app.set("trust proxy", 1);

// CORS - CRITICAL
const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    console.warn("[CORS] Blocked origin:", origin);
    cb(new Error("CORS not allowed"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
  exposedHeaders: ["X-Credits-Remaining"],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

// ════════════════════════════════════════════════════
// RATE LIMITING
// ════════════════════════════════════════════════════
const mkLimiter = (windowMs, max) => rateLimit({
  windowMs, max, standardHeaders: false, legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => res.status(429).json({ error: "Trop de requêtes" })
});

app.use(mkLimiter(15 * 60 * 1000, 300));
const searchLimiter = mkLimiter(60 * 1000, 20);
const osintLimiter = mkLimiter(60 * 1000, 30);

// ════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ════════════════════════════════════════════════════
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Non authentifié" });
  try {
    const { data: { user }, error } = await supabaseAdmin.auth.getUser(auth.slice(7));
    if (error || !user) return res.status(401).json({ error: "Token invalide" });
    req.user = user;
    next();
  } catch (e) {
    console.error("[AUTH_ERROR]", e.message);
    res.status(401).json({ error: "Erreur authentification" });
  }
}

// ════════════════════════════════════════════════════
// PUBLIC ROUTES
// ════════════════════════════════════════════════════
app.get("/", (req, res) => res.json({ status: "online", service: "rapace-backend", version: "2.0.0" }));
app.get("/health", (req, res) => res.json({ status: "ok", uptime: process.uptime() }));
app.get("/api/status", (req, res) => res.json({ status: "online", version: "2.0.0" }));
app.get("/api/csrf-nonce", (req, res) => res.json({ nonce: crypto.randomBytes(32).toString("hex") }));

app.post("/validate-login", async (req, res) => {
  const { email, csrfNonce } = req.body;
  if (!email || typeof email !== "string") {
    return res.status(400).json({ success: false, message: "Email invalide" });
  }
  if (!csrfNonce || typeof csrfNonce !== "string") {
    return res.status(400).json({ success: false, message: "Nonce invalide" });
  }
  res.json({ success: true });
});

app.post("/api/notify-login", requireAuth, async (req, res) => {
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
// SOCKET.IO
// ════════════════════════════════════════════════════
const io = socketIo(server, { cors: corsOptions, maxHttpBufferSize: 1e4 });
let onlineUsers = 0;
const connectedSockets = new Map();

io.on("connection", (socket) => {
  onlineUsers++;
  io.emit("users", onlineUsers);

  socket.on("chat:join", (data) => {
    const pseudo = (data?.pseudo || "Anonymous").substring(0, 50);
    connectedSockets.set(socket.id, { pseudo });
    io.emit("chat:message", {
      id: `sys_${Date.now()}`,
      pseudo: "SYSTEM",
      content: `${pseudo} a rejoint le chat`,
      created_at: new Date().toISOString(),
      isSystem: true
    });
  });

  socket.on("chat:send", (data) => {
    if (!data?.content) return;
    const content = data.content.substring(0, 1000);
    const pseudo = (data.pseudo || "Anonymous").substring(0, 50);
    io.emit("chat:message", {
      id: `msg_${Date.now()}`,
      pseudo,
      content,
      created_at: new Date().toISOString()
    });
  });

  socket.on("disconnect", () => {
    onlineUsers = Math.max(0, onlineUsers - 1);
    const user = connectedSockets.get(socket.id);
    if (user) {
      io.emit("chat:message", {
        id: `sys_${Date.now()}`,
        pseudo: "SYSTEM",
        content: `${user.pseudo} a quitté le chat`,
        created_at: new Date().toISOString(),
        isSystem: true
      });
      connectedSockets.delete(socket.id);
    }
    io.emit("users", onlineUsers);
  });
});

// ════════════════════════════════════════════════════
// SEEKNOW WRAPPER
// ════════════════════════════════════════════════════
async function seeknowFetch(path, { method = "GET", body = null, searchParams = {} } = {}) {
  const url = new URL(`https://see-know.eu/api/v1${path}`);
  Object.entries(searchParams).forEach(([k, v]) => url.searchParams.set(k, v));
  
  const opts = {
    method,
    headers: { "X-API-Key": SEEKNOW_API_KEY, "Content-Type": "application/json" }
  };
  if (body) opts.body = JSON.stringify(body);
  
  const res = await fetch(url.toString(), opts);
  const data = await res.json();
  
  if (!res.ok) {
    const errMap = {
      401: "Clé API SeeKnow invalide",
      402: "Crédits insuffisants",
      403: "Accès refusé",
      404: "Résultat non trouvé",
      429: "Limite de requêtes atteinte"
    };
    throw { status: res.status, error: errMap[res.status] || data.message || "Erreur SeeKnow" };
  }
  return data;
}

// ════════════════════════════════════════════════════
// AUTH ENDPOINTS
// ════════════════════════════════════════════════════
app.get("/api/v1/auth/me", requireAuth, async (req, res) => {
  try {
    const { data: user } = await supabaseAdmin.from("users").select("*").eq("auth_id", req.user.id).maybeSingle();
    res.json({
      auth_id: user?.auth_id,
      email: user?.email,
      username: user?.username || req.user.email?.split("@")[0],
      plan: user?.plan || "free",
      credits: user?.credits ?? 10,
      max_credits: user?.max_credits || 10,
      is_admin: ADMIN_IDS.has(req.user.id)
    });
  } catch (e) {
    console.error("[AUTH_ME_ERROR]", e.message);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/v1/auth/track-session", requireAuth, async (req, res) => {
  const { browser, device } = req.body;
  const ip = req.ip;
  try {
    await supabaseAdmin.from("sessions").insert({
      auth_id: req.user.id,
      browser: (browser || "Unknown").substring(0, 100),
      device: (device || "Unknown").substring(0, 100),
      ip_address: ip,
      last_activity: new Date().toISOString()
    });
    res.json({ success: true });
  } catch (e) {
    res.json({ success: true });
  }
});

app.get("/api/v1/auth/sessions", requireAuth, async (req, res) => {
  try {
    const { data } = await supabaseAdmin.from("sessions").select("*").eq("auth_id", req.user.id).limit(10);
    res.json({ success: true, sessions: data || [] });
  } catch (e) {
    res.json({ success: true, sessions: [] });
  }
});

app.delete("/api/v1/auth/sessions/:id", requireAuth, async (req, res) => {
  try {
    await supabaseAdmin.from("sessions").delete().eq("id", req.params.id).eq("auth_id", req.user.id);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: true });
  }
});

app.post("/api/v1/auth/revoke-all-sessions", requireAuth, async (req, res) => {
  try {
    await supabaseAdmin.from("sessions").delete().eq("auth_id", req.user.id);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: true });
  }
});

app.post("/api/v1/auth/update-password", requireAuth, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: "Mot de passe trop faible" });
  try {
    await supabaseAdmin.auth.admin.updateUserById(req.user.id, { password: newPassword });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// ════════════════════════════════════════════════════
// SEARCH ENDPOINTS
// ════════════════════════════════════════════════════
app.post("/api/v1/search", requireAuth, searchLimiter, async (req, res) => {
  const { query, type = "auto" } = req.body;
  if (!query || query.length < 2) return res.status(400).json({ error: "Requête invalide" });
  try {
    const data = await seeknowFetch("/search", { method: "POST", body: { query, type } });
    res.json(data);
  } catch (e) {
    if (e.status) return res.status(e.status).json({ error: e.error });
    res.status(502).json({ error: "Erreur API SeeKnow" });
  }
});

app.post("/api/v1/stealer", requireAuth, searchLimiter, async (req, res) => {
  const { query, type = "auto" } = req.body;
  if (!query || query.length < 2) return res.status(400).json({ error: "Requête invalide" });
  try {
    const data = await seeknowFetch("/stealer", { method: "POST", body: { query, type } });
    res.json(data);
  } catch (e) {
    if (e.status) return res.status(e.status).json({ error: e.error });
    res.status(502).json({ error: "Erreur API SeeKnow" });
  }
});

// ════════════════════════════════════════════════════
// OSINT ENDPOINTS
// ════════════════════════════════════════════════════
function createOsintRoute(path, paramName, seeknowPath) {
  app.get(`/api/v1/osint${path}`, requireAuth, osintLimiter, async (req, res) => {
    const value = req.query[paramName];
    if (!value || typeof value !== "string") return res.status(400).json({ error: `Paramètre '${paramName}' requis` });
    try {
      const data = await seeknowFetch(seeknowPath, { method: "GET", searchParams: { [paramName]: value.substring(0, 200) } });
      res.json(data);
    } catch (e) {
      if (e.status) return res.status(e.status).json({ error: e.error });
      res.status(502).json({ error: "Erreur OSINT" });
    }
  });
}

createOsintRoute("/discord-user", "query", "/discord/user");
createOsintRoute("/discord-roblox", "query", "/discord/to-roblox");
createOsintRoute("/github", "username", "/username/github");
createOsintRoute("/twitter", "username", "/username/twitter");
createOsintRoute("/tiktok", "username", "/username/tiktok");
createOsintRoute("/reddit", "username", "/username/reddit");
createOsintRoute("/social", "username", "/username/social");
createOsintRoute("/username-history", "username", "/username/history");
createOsintRoute("/xbox", "username", "/gaming/xbox");
createOsintRoute("/roblox", "username", "/gaming/roblox");
createOsintRoute("/minecraft", "username", "/gaming/minecraft");
createOsintRoute("/ip", "ip", "/network/ip");
createOsintRoute("/email-check", "email", "/network/email-check");
createOsintRoute("/phone", "phone", "/network/phone");
createOsintRoute("/domain-intel", "domain", "/domain/intel");
createOsintRoute("/whois", "domain", "/domain/whois");

// ════════════════════════════════════════════════════
// ACCOUNT ENDPOINTS
// ════════════════════════════════════════════════════
app.get("/api/v1/sk-credits", requireAuth, async (req, res) => {
  try {
    const data = await seeknowFetch("/credits");
    res.json(data);
  } catch (e) {
    if (e.status) return res.status(e.status).json({ error: e.error });
    res.status(502).json({ error: "Impossible de récupérer les crédits" });
  }
});

app.get("/api/v1/account/notifications", requireAuth, (req, res) => {
  res.json({ success: true, notifications: [], unread_count: 0 });
});

app.post("/api/v1/account/notifications/read-all", requireAuth, (req, res) => {
  res.json({ success: true });
});

app.delete("/api/v1/account/notifications/:id", requireAuth, (req, res) => {
  res.json({ success: true });
});

app.get("/api/v1/security/logs", requireAuth, async (req, res) => {
  try {
    const { data } = await supabaseAdmin.from("security_logs").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false }).limit(20);
    res.json({ success: true, logs: data || [] });
  } catch (e) {
    res.json({ success: true, logs: [] });
  }
});

app.get("/api/v1/account/activities", requireAuth, async (req, res) => {
  try {
    const { data } = await supabaseAdmin.from("security_logs").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false }).limit(50);
    res.json({ success: true, activities: data || [] });
  } catch (e) {
    res.json({ success: true, activities: [] });
  }
});

app.get("/api/v1/account/key-reset-status", requireAuth, (req, res) => {
  res.json({ canReset: true });
});

app.post("/api/v1/account/reset-api-key", requireAuth, (req, res) => {
  const newKey = "sk-" + crypto.randomBytes(24).toString("hex").slice(0, 32);
  res.json({ success: true, newKey });
});

app.post("/api/v1/account/update-preferences", requireAuth, async (req, res) => {
  const { displayName } = req.body;
  if (!displayName || typeof displayName !== "string") return res.status(400).json({ error: "Nom invalide" });
  try {
    await supabaseAdmin.from("users").update({ username: displayName.substring(0, 50) }).eq("auth_id", req.user.id);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: true });
  }
});

// ════════════════════════════════════════════════════
// HISTORY ENDPOINTS
// ════════════════════════════════════════════════════
app.post("/api/v1/history", requireAuth, searchLimiter, async (req, res) => {
  const { query, search_type } = req.body;
  if (!query) return res.status(400).json({ error: "Requête invalide" });
  try {
    await supabaseAdmin.from("search_logs").insert({
      auth_id: req.user.id,
      query: query.substring(0, 300),
      search_type: (search_type || "auto").substring(0, 50),
      ip_address: req.ip
    });
    res.json({ success: true });
  } catch (e) {
    res.json({ success: true });
  }
});

app.get("/api/v1/history", requireAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const page = Math.max(parseInt(req.query.page) || 0, 0);
  try {
    const { data } = await supabaseAdmin.from("search_logs").select("*").eq("auth_id", req.user.id).order("created_at", { ascending: false }).range(page * limit, (page + 1) * limit - 1);
    res.json({ success: true, history: data || [] });
  } catch (e) {
    res.json({ success: true, history: [] });
  }
});

// ════════════════════════════════════════════════════
// REGISTER
// ════════════════════════════════════════════════════
app.post("/api/v1/register", requireAuth, async (req, res) => {
  const { username } = req.body;
  try {
    const existing = await supabaseAdmin.from("users").select("id").eq("auth_id", req.user.id).maybeSingle();
    if (!existing.data) {
      await supabaseAdmin.from("users").insert({
        auth_id: req.user.id,
        email: req.user.email,
        username: (username || req.user.email?.split("@")[0]).substring(0, 50),
        plan: "free",
        credits: 10,
        max_credits: 10
      });
    }
    res.json({ success: true });
  } catch (e) {
    res.json({ success: true });
  }
});

// ════════════════════════════════════════════════════
// ERROR HANDLING
// ════════════════════════════════════════════════════
app.use((req, res) => {
  console.warn("[404]", req.method, req.path);
  res.status(404).json({ error: "Route non trouvée" });
});

app.use((err, req, res, next) => {
  console.error("[ERROR]", err.message);
  res.status(500).json({ error: "Erreur interne" });
});

// ════════════════════════════════════════════════════
// START
// ════════════════════════════════════════════════════
server.listen(PORT, () => {
  console.log(`✓ Server running on port ${PORT}`);
  console.log(`✓ CORS: ${ALLOWED_ORIGINS.join(", ")}`);
  console.log(`✓ Environment: ${NODE_ENV}`);
});

process.on("unhandledRejection", (err) => console.error("[UNHANDLED]", err));
