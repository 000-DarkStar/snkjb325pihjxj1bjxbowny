const express   = require("express");
const http      = require("http");
const socketIo  = require("socket.io");
const cors      = require("cors");
const rateLimit = require("express-rate-limit");
const helmet    = require("helmet");
const validator = require("validator");
const crypto    = require("crypto");
const fs        = require("fs");
const path      = require("path");
const { createClient } = require("@supabase/supabase-js");

const app    = express();
const server = http.createServer(app);
app.set("trust proxy", 1);

// ==================== CONFIG ====================
const PORT             = process.env.PORT || 3000;
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";
const ALLOWED_ORIGINS  = (process.env.ALLOWED_ORIGINS || "")
    .split(",").map(s => s.trim()).filter(Boolean);
const SUPABASE_URL         = process.env.SUPABASE_URL || "";
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || "";
const supabaseAdmin = (SUPABASE_URL && SUPABASE_SERVICE_KEY)
    ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } })
    : null;

const ADMIN_UIDS = new Set([
    "5a819614-acac-4c54-a529-d15da447a47a",
    "d834eeb8-7eb5-4c61-a46e-e3c6d7fcadae"
]);

// ==================== LOGGING ====================
const LOG_DIR  = path.join(__dirname, "logs");
const LOG_FILE = path.join(LOG_DIR, "security.log");
if (!fs.existsSync(LOG_DIR)) { try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (_) {} }
function log(level, event, details = {}) {
    const entry = JSON.stringify({ timestamp: new Date().toISOString(), level, event, ...details });
    if (process.env.NODE_ENV !== "production") process.stdout.write(`[${level}] ${event} ${JSON.stringify(details)}\n`);
    try { fs.appendFileSync(LOG_FILE, entry + "\n"); } catch (_) {}
}

// ==================== SECURITY HEADERS ====================
app.use(helmet({
    contentSecurityPolicy: false,
    hsts:           { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard:     { action: "deny" },
    noSniff:        true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));
app.disable("x-powered-by");

// ==================== CORS ====================
const corsOptions = {
    origin: (origin, cb) => {
        if (!origin) return cb(null, true);
        if (!ALLOWED_ORIGINS.length || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        log("WARN", "cors_blocked", { origin });
        cb(new Error("Not allowed by CORS"));
    },
    methods:        ["GET", "POST", "OPTIONS"],
    credentials:    true,
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"]
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ==================== SOCKET.IO ====================
const io = socketIo(server, {
    cors: {
        origin: (origin, cb) => {
            if (!origin) return cb(null, true);
            if (!ALLOWED_ORIGINS.length || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
            cb(new Error("Not allowed"));
        },
        methods: ["GET", "POST"], credentials: true
    },
    maxHttpBufferSize: 1e4
});

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

// ==================== RATE LIMITERS ====================
const mkLimiter = (windowMs, max, msg) => rateLimit({
    windowMs, max, standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req) => req.ip,
    handler: (req, res) => { log("WARN", "rate_limit", { ip: req.ip, path: req.path }); res.status(429).json({ error: msg }); }
});
app.use(mkLimiter(15 * 60 * 1000, 300, "Trop de requêtes."));
const captchaLimiter     = mkLimiter(60 * 1000,      10, "Trop de tentatives captcha.");
const registerLimiter    = mkLimiter(60 * 60 * 1000,  3, "Trop d'inscriptions.");
const loginLimiter       = mkLimiter(15 * 60 * 1000,  5, "Trop de tentatives.");
const statsLimiter       = mkLimiter(60 * 1000,       30, "Trop de requêtes stats.");
const maintenanceLimiter = mkLimiter(60 * 1000,       60, "Trop de requêtes maintenance.");
const logLimiter         = mkLimiter(60 * 1000,       30, "Trop de requêtes log.");

// ==================== AUTH MIDDLEWARE ====================
async function requireAuth(req, res, next) {
    const auth = req.headers["authorization"];
    if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Non authentifié" });
    // Si supabaseAdmin pas dispo (env vars manquants) → laisse passer en dev
    if (!supabaseAdmin) { log("WARN", "auth_skipped_no_client"); return next(); }
    try {
        const { data: { user }, error } = await supabaseAdmin.auth.getUser(auth.slice(7));
        if (error || !user) return res.status(401).json({ error: "Token invalide" });
        req.user = user;
        next();
    } catch (_) { res.status(401).json({ error: "Erreur auth" }); }
}

async function requireAdmin(req, res, next) {
    const auth = req.headers["authorization"];
    if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Non authentifié" });
    if (!supabaseAdmin) return res.status(503).json({ error: "Service indisponible" });
    try {
        const { data: { user }, error } = await supabaseAdmin.auth.getUser(auth.slice(7));
        if (error || !user) return res.status(401).json({ error: "Token invalide" });
        if (!ADMIN_UIDS.has(user.id)) { log("WARN", "admin_denied", { uid: user.id, ip: req.ip }); return res.status(403).json({ error: "Accès refusé" }); }
        req.user = user;
        next();
    } catch (_) { res.status(401).json({ error: "Erreur auth" }); }
}

// ==================== VALIDATION ====================
const PWD_REGEX        = /^(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,72}$/;
const validateEmail    = e => !!(e && typeof e === "string" && validator.isEmail(e.trim()) && e.length <= 254);
const validatePassword = p => !!(p && typeof p === "string" && PWD_REGEX.test(p));
const sanitize         = (s, n = 1000) => typeof s === "string" ? validator.escape(s.trim()).substring(0, n) : "";

// ==================== CSRF ====================
const csrfNonces = new Map();
const generateCsrfNonce = () => { const n = crypto.randomBytes(32).toString("hex"); csrfNonces.set(n, { expiresAt: Date.now() + 5 * 60 * 1000 }); return n; };
const consumeCsrfNonce = n => { if (!n || !csrfNonces.has(n)) return false; const { expiresAt } = csrfNonces.get(n); csrfNonces.delete(n); return Date.now() < expiresAt; };
setInterval(() => { const now = Date.now(); for (const [k, v] of csrfNonces) if (now > v.expiresAt) csrfNonces.delete(k); }, 10 * 60 * 1000);

// ==================== MAINTENANCE CACHE (15s TTL) ====================
let _mntCache = null, _mntTs = 0;
async function getMnt() {
    if (_mntCache !== null && Date.now() - _mntTs < 15000) return _mntCache;
    if (!supabaseAdmin) { _mntCache = { active: false }; _mntTs = Date.now(); return _mntCache; }
    try {
        const { data } = await supabaseAdmin.from("system_settings").select("value").eq("key", "maintenance").single();
        const v = data?.value;
        _mntCache = v ? (typeof v === "string" ? JSON.parse(v) : v) : { active: false };
    } catch (_) { _mntCache = { active: false }; }
    _mntTs = Date.now();
    return _mntCache;
}
function invalidateMnt() { _mntCache = null; _mntTs = 0; }

// ==================== MAINTENANCE GUARD ====================
const MNT_WHITELIST = new Set(["/health", "/api/status", "/api/csrf-nonce", "/api/maintenance", "/api/log-event", "/favicon.ico"]);
async function maintenanceGuard(req, res, next) {
    if (MNT_WHITELIST.has(req.path)) return next();
    const st = await getMnt();
    if (!st?.active) return next();
    const auth = req.headers["authorization"];
    if (auth?.startsWith("Bearer ") && supabaseAdmin) {
        try {
            const { data: { user } } = await supabaseAdmin.auth.getUser(auth.slice(7));
            if (user && ADMIN_UIDS.has(user.id)) return next();
        } catch (_) {}
    }
    log("INFO", "mnt_blocked", { ip: req.ip, path: req.path });
    res.status(503).json({ error: "maintenance", message: st.message || "La plateforme est en maintenance.", end_time: st.end_time || null, retry_after: 60 });
}
app.use(maintenanceGuard);

// ==================== STATS ====================
let statsCache = { indexedLines: "1.9B", totalSearches: 0, registeredUsers: 0 };
async function refreshStats() {
    if (!supabaseAdmin) return;
    try {
        const [{ count: users }, { count: searches }] = await Promise.all([
            supabaseAdmin.from("users").select("*", { count: "exact", head: true }),
            supabaseAdmin.from("search_logs").select("*", { count: "exact", head: true })
        ]);
        statsCache = { indexedLines: "1.9B", totalSearches: searches ?? 0, registeredUsers: users ?? 0 };
    } catch (_) {}
}
refreshStats();
setInterval(refreshStats, 5 * 60 * 1000);

// ==================== SANCTIONS CACHE ====================
const sanctionCache = new Map();
async function getSanction(authId) {
    const cached = sanctionCache.get(authId);
    if (cached && Date.now() - cached._ts < 30000) return cached;
    if (!supabaseAdmin) return { muted: false, banned: false, mutedUntil: null };
    try {
        const { data: user } = await supabaseAdmin.from("users").select("id").eq("auth_id", authId).single();
        if (!user) return { muted: false, banned: false, mutedUntil: null };
        const { data: sanctions } = await supabaseAdmin.from("sanctions").select("type, expires_at").eq("user_id", user.id).eq("active", true).or(`expires_at.is.null,expires_at.gt.${new Date().toISOString()}`);
        const mute = sanctions?.find(s => s.type === "mute");
        const result = { muted: !!mute, banned: !!(sanctions?.find(s => s.type === "ban")), mutedUntil: mute?.expires_at ?? null, _ts: Date.now() };
        sanctionCache.set(authId, result);
        return result;
    } catch (_) { return { muted: false, banned: false, mutedUntil: null }; }
}

// ==================== SOCKET.IO ====================
let onlineUsers = 0;
const connectedSockets = new Map();
const chatRateMap = new Map();

io.on("connection", async (socket) => {
    const st = await getMnt();
    if (st?.active) {
        socket.emit("maintenance", { message: st.message, end_time: st.end_time });
        setTimeout(() => socket.disconnect(true), 300);
        return;
    }
    onlineUsers++;
    io.emit("users", onlineUsers);

    socket.on("chat:join", (data) => {
        if (!data?.pseudo || typeof data.pseudo !== "string") return;
        const pseudo = sanitize(data.pseudo, 50);
        const authId = typeof data.authId === "string" ? data.authId.substring(0, 64) : null;
        connectedSockets.set(socket.id, { pseudo, authId });
        io.emit("chat:message", { id: `sys_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`, pseudo: "SYSTEM", content: `${pseudo} a rejoint le chat`, created_at: new Date().toISOString(), isSystem: true });
    });

    socket.on("chat:send", async (data) => {
        if (!data || typeof data.pseudo !== "string" || typeof data.content !== "string") { socket.emit("chat:error", { message: "Données invalides" }); return; }
        const now = Date.now(), last = chatRateMap.get(socket.id) || 0;
        if (now - last < 1000) { socket.emit("chat:error", { message: "Un message par seconde maximum." }); return; }
        chatRateMap.set(socket.id, now);
        const content = sanitize(data.content, 1000);
        if (!content) { socket.emit("chat:error", { message: "Message vide" }); return; }
        const sd = connectedSockets.get(socket.id);
        if (sd?.authId) {
            const s = await getSanction(sd.authId);
            if (s.banned) { socket.emit("chat:error", { message: "Votre compte est banni." }); return; }
            if (s.muted) { socket.emit("chat:error", { message: `Vous êtes réduit au silence${s.mutedUntil ? ` jusqu'à ${new Date(s.mutedUntil).toLocaleTimeString("fr-FR")}` : ""}.` }); return; }
        }
        io.emit("chat:message", { id: data.id || `msg_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`, pseudo: sanitize(data.pseudo, 50), content, created_at: new Date().toISOString() });
    });

    socket.on("chat:typing", (data) => {
        if (data && typeof data.pseudo === "string") socket.broadcast.emit("chat:userTyping", { pseudo: sanitize(data.pseudo, 50), isTyping: Boolean(data.isTyping) });
    });

    socket.on("admin:invalidate", (data) => { if (data?.authId) sanctionCache.delete(data.authId); });

    socket.on("admin:maintenance_toggle", async () => {
        const sd = connectedSockets.get(socket.id);
        if (!sd?.authId || !ADMIN_UIDS.has(sd.authId)) return;
        invalidateMnt();
        const newSt = await getMnt();
        if (newSt?.active) {
            for (const [sid, info] of connectedSockets) {
                if (!ADMIN_UIDS.has(info.authId || "")) {
                    const s = io.sockets.sockets.get(sid);
                    if (s) { s.emit("maintenance", { message: newSt.message, end_time: newSt.end_time }); setTimeout(() => s.disconnect(true), 300); }
                }
            }
        }
    });

    socket.on("disconnect", () => {
        onlineUsers = Math.max(0, onlineUsers - 1);
        const user = connectedSockets.get(socket.id);
        if (user) {
            io.emit("chat:message", { id: `sys_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`, pseudo: "SYSTEM", content: `${user.pseudo} a quitté le chat`, created_at: new Date().toISOString(), isSystem: true });
            connectedSockets.delete(socket.id);
        }
        chatRateMap.delete(socket.id);
        io.emit("users", Math.max(0, onlineUsers));
    });
});

// ==================== ROUTES ====================
app.get("/favicon.ico", (req, res) => res.status(204).end());
app.get("/health",      (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));
app.get("/api/status",  (req, res) => res.json({ status: "online", onlineUsers, timestamp: new Date().toISOString() }));
app.get("/api/csrf-nonce", (req, res) => res.json({ nonce: generateCsrfNonce() }));

// Maintenance — public
app.get("/api/maintenance", maintenanceLimiter, async (req, res) => {
    try {
        const st = await getMnt();
        res.json({
            active: !!st?.active, message: st?.message || null, end_time: st?.end_time || null,
            progress: st?.progress ?? null,
            steps: Array.isArray(st?.steps) ? st.steps.map(s => ({ name: String(s.name || "").substring(0, 200), desc: String(s.desc || "").substring(0, 500), status: ["done","inprog","todo"].includes(s.status) ? s.status : "todo" })) : []
        });
    } catch (_) { res.json({ active: false }); }
});

// Maintenance — admin toggle
app.post("/api/admin/maintenance", requireAdmin, maintenanceLimiter, async (req, res) => {
    if (!supabaseAdmin) return res.status(503).json({ error: "Service indisponible" });
    const { active, message, end_time, progress, steps } = req.body;
    if (typeof active !== "boolean") return res.status(400).json({ error: "'active' requis" });
    try {
        const cur = await getMnt();
        const newSt = {
            ...cur, active: Boolean(active),
            message:    typeof message === "string" ? sanitize(message, 500) : (cur?.message || ""),
            end_time:   end_time ?? null,
            progress:   typeof progress === "number" ? Math.max(0, Math.min(100, progress)) : (cur?.progress ?? 0),
            steps:      Array.isArray(steps) ? steps.map(s => ({ name: sanitize(s.name || "", 200), desc: sanitize(s.desc || "", 500), status: ["done","inprog","todo"].includes(s.status) ? s.status : "todo" })) : (cur?.steps || []),
            started_at: active && !cur?.started_at ? new Date().toISOString() : (cur?.started_at || null),
            updated_at: new Date().toISOString()
        };
        const { error } = await supabaseAdmin.from("system_settings").upsert({ key: "maintenance", value: newSt }, { onConflict: "key" });
        if (error) throw error;
        invalidateMnt();
        log("INFO", "mnt_updated", { by: req.user.id, active: newSt.active, ip: req.ip });
        res.json({ success: true, state: newSt });
    } catch (e) { log("ERROR", "mnt_fail", { msg: e.message }); res.status(500).json({ error: "Erreur mise à jour" }); }
});

// Log sécurité — sans auth (pour capturer les login échoués)
app.post("/api/log-event", logLimiter, async (req, res) => {
    const { action_type, action_description, user_id } = req.body;
    if (!action_type || typeof action_type !== "string") return res.status(400).json({ error: "action_type requis" });
    if (!supabaseAdmin) return res.json({ success: true });
    try {
        await supabaseAdmin.from("security_logs").insert({
            user_id:            user_id || null,
            action_type:        sanitize(action_type, 100),
            action_description: sanitize(action_description || "", 300),
            ip_address:         req.ip
        });
        res.json({ success: true });
    } catch (_) { res.json({ success: true }); }
});

// Stats — nécessite auth
app.get("/api/stats/dashboard", requireAuth, statsLimiter, (req, res) => {
    res.json({ ...statsCache, timestamp: new Date().toISOString() });
});

// Captcha
app.post("/verify-captcha", captchaLimiter, async (req, res) => {
    const { token, csrfNonce } = req.body;
    if (!consumeCsrfNonce(csrfNonce))       return res.status(403).json({ success: false, message: "CSRF invalide" });
    if (!token || typeof token !== "string") return res.status(400).json({ success: false, message: "Token manquant" });
    if (token.length > 2048)                return res.status(400).json({ success: false, message: "Token invalide" });
    if (!TURNSTILE_SECRET)                  return res.status(500).json({ success: false, message: "Config incomplète" });
    try {
        const form = new URLSearchParams();
        form.append("secret", TURNSTILE_SECRET); form.append("response", token); form.append("remoteip", req.ip);
        const cf = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form.toString() });
        const cfData = await cf.json();
        if (!cfData.success) { log("WARN", "captcha_fail", { ip: req.ip }); return res.status(400).json({ success: false, message: "Captcha invalide" }); }
        res.json({ success: true });
    } catch (_) { res.status(500).json({ success: false, message: "Erreur captcha" }); }
});

// Register + Login validation
app.post("/validate-register", registerLimiter, (req, res) => {
    const { email, password, csrfNonce } = req.body;
    if (!consumeCsrfNonce(csrfNonce))  return res.status(403).json({ success: false, message: "CSRF invalide" });
    if (!validateEmail(email))          return res.status(400).json({ success: false, message: "Email invalide" });
    if (!validatePassword(password))    return res.status(400).json({ success: false, message: "Mot de passe trop faible (8+ car, 1 maj, 1 chiffre, 1 symbole)" });
    res.json({ success: true });
});

app.post("/validate-login", loginLimiter, (req, res) => {
    const { email, csrfNonce } = req.body;
    if (!consumeCsrfNonce(csrfNonce)) return res.status(403).json({ success: false, message: "CSRF invalide" });
    if (!validateEmail(email))         return res.status(400).json({ success: false, message: "Identifiants incorrects" });
    res.json({ success: true });
});

app.use((req, res) => res.status(404).json({ error: "Route non trouvée" }));
app.use((err, req, res, _next) => { log("ERROR", "unhandled", { msg: err.message }); res.status(500).json({ error: "Erreur interne" }); });

server.listen(PORT, () => log("INFO", "server_start", { port: PORT }));
