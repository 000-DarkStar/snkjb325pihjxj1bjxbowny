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

// ============================================================
// FIX CRITIQUE — trust proxy pour Render (X-Forwarded-For)
// Sans ça express-rate-limit lance ERR_ERL_UNEXPECTED_X_FORWARDED_FOR
// ============================================================
app.set("trust proxy", 1);

// ==================== CONFIGURATION ====================
const PORT             = process.env.PORT || 3000;
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";
const ALLOWED_ORIGINS  = (process.env.ALLOWED_ORIGINS || "")
    .split(",").map(s => s.trim()).filter(Boolean);

const SUPABASE_URL         = process.env.SUPABASE_URL || "";
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || "";
const supabaseAdmin = (SUPABASE_URL && SUPABASE_SERVICE_KEY)
    ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } })
    : null;

// ==================== LOGGING ====================
const LOG_DIR  = path.join(__dirname, "logs");
const LOG_FILE = path.join(LOG_DIR, "security.log");
if (!fs.existsSync(LOG_DIR)) { try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (_) {} }

function log(level, event, details = {}) {
    const entry = JSON.stringify({ timestamp: new Date().toISOString(), level, event, ...details });
    if (process.env.NODE_ENV !== "production") process.stdout.write(`[${level}] ${event}\n`);
    try { fs.appendFileSync(LOG_FILE, entry + "\n"); } catch (_) {}
}

// ==================== HELMET ====================
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
        methods: ["GET", "POST"],
        credentials: true
    }
});

// ==================== BODY PARSING ====================
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// ==================== RATE LIMITERS ====================
const mkLimiter = (windowMs, max, msg) => rateLimit({
    windowMs, max,
    standardHeaders: true,
    legacyHeaders:   false,
    handler: (req, res) => {
        log("WARN", "rate_limit", { ip: req.ip, path: req.path });
        res.status(429).json({ error: msg });
    }
});

// Global
app.use(mkLimiter(15 * 60 * 1000, 300, "Trop de requêtes. Réessayez plus tard."));

const captchaLimiter  = mkLimiter(60 * 1000,      10, "Trop de tentatives captcha.");
const registerLimiter = mkLimiter(60 * 60 * 1000,  3, "Trop d'inscriptions. Réessayez dans 1h.");
const loginLimiter    = mkLimiter(15 * 60 * 1000,  5, "Trop de tentatives. Réessayez dans 15 min.");
const statsLimiter    = mkLimiter(60 * 1000,       30, "Trop de requêtes stats.");

// ==================== JWT MIDDLEWARE ====================
async function requireAuth(req, res, next) {
    const auth = req.headers["authorization"];
    if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Non authentifié" });
    const token = auth.slice(7);
    if (!supabaseAdmin) return next();
    try {
        const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: "Token invalide" });
        req.user = user;
        next();
    } catch (_) { res.status(401).json({ error: "Erreur auth" }); }
}

// ==================== VALIDATION & SANITIZE ====================
const PWD_REGEX = /^(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/;
const validateEmail    = e => !!(e && typeof e === "string" && validator.isEmail(e.trim()));
const validatePassword = p => !!(p && typeof p === "string" && PWD_REGEX.test(p));
const sanitize         = (s, n = 1000) => typeof s === "string" ? validator.escape(s.trim()).substring(0, n) : "";

// ==================== CSRF NONCES ====================
const csrfNonces = new Map();
const generateCsrfNonce = () => {
    const n = crypto.randomBytes(32).toString("hex");
    csrfNonces.set(n, { expiresAt: Date.now() + 5 * 60 * 1000 });
    return n;
};
const consumeCsrfNonce = n => {
    if (!n || !csrfNonces.has(n)) return false;
    const { expiresAt } = csrfNonces.get(n);
    csrfNonces.delete(n);
    return Date.now() < expiresAt;
};
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of csrfNonces) if (now > v.expiresAt) csrfNonces.delete(k);
}, 10 * 60 * 1000);

// ==================== STATS CACHE ====================
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

// ==================== CACHE SANCTIONS (chat) ====================
// Évite un appel DB à chaque message — TTL 30 secondes
const sanctionCache   = new Map();
const SANCTION_TTL_MS = 30 * 1000;

async function getSanction(authId) {
    const cached = sanctionCache.get(authId);
    if (cached && Date.now() - cached._ts < SANCTION_TTL_MS) return cached;
    if (!supabaseAdmin) return { muted: false, banned: false, mutedUntil: null };
    try {
        const { data: user } = await supabaseAdmin
            .from("users").select("id").eq("auth_id", authId).single();
        if (!user) return { muted: false, banned: false, mutedUntil: null };

        const now = new Date().toISOString();
        const { data: sanctions } = await supabaseAdmin
            .from("sanctions")
            .select("type, expires_at")
            .eq("user_id", user.id)
            .eq("active", true)
            .or(`expires_at.is.null,expires_at.gt.${now}`);

        const muteEntry = sanctions?.find(s => s.type === "mute");
        const result = {
            muted:      !!muteEntry,
            banned:     !!(sanctions?.find(s => s.type === "ban")),
            mutedUntil: muteEntry?.expires_at ?? null,
            _ts:        Date.now()
        };
        sanctionCache.set(authId, result);
        return result;
    } catch (_) { return { muted: false, banned: false, mutedUntil: null }; }
}

// ==================== SOCKET.IO HANDLERS ====================
let onlineUsers = 0;
const connectedSockets = new Map(); // socketId → { pseudo, authId }
const chatRateMap      = new Map(); // socketId → lastMsgTimestamp
const CHAT_RATE_MS     = 1000;      // 1 msg/seconde max

io.on("connection", (socket) => {
    onlineUsers++;
    io.emit("users", onlineUsers);

    socket.on("chat:join", (data) => {
        if (!data?.pseudo || typeof data.pseudo !== "string") return;
        const pseudo = sanitize(data.pseudo, 50);
        const authId = typeof data.authId === "string" ? data.authId : null;
        connectedSockets.set(socket.id, { pseudo, authId });
        io.emit("chat:message", {
            id:         `sys_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
            pseudo:     "SYSTEM",
            content:    `${pseudo} a rejoint le chat`,
            created_at: new Date().toISOString(),
            isSystem:   true
        });
    });

    socket.on("chat:send", async (data) => {
        if (!data || typeof data.pseudo !== "string" || typeof data.content !== "string") {
            socket.emit("chat:error", { message: "Données invalides" });
            return;
        }

        // Rate limit : 1 message/seconde
        const now  = Date.now();
        const last = chatRateMap.get(socket.id) || 0;
        if (now - last < CHAT_RATE_MS) {
            socket.emit("chat:error", { message: "Un message par seconde maximum." });
            return;
        }
        chatRateMap.set(socket.id, now);

        const content = sanitize(data.content, 1000);
        if (!content) { socket.emit("chat:error", { message: "Message vide" }); return; }

        // Vérification sanctions
        const sd = connectedSockets.get(socket.id);
        if (sd?.authId) {
            const sanction = await getSanction(sd.authId);
            if (sanction.banned) {
                socket.emit("chat:error", { message: "Votre compte est banni." });
                return;
            }
            if (sanction.muted) {
                const until = sanction.mutedUntil
                    ? ` jusqu'à ${new Date(sanction.mutedUntil).toLocaleTimeString("fr-FR")}`
                    : "";
                socket.emit("chat:error", { message: `Vous êtes réduit au silence${until}.` });
                return;
            }
        }

        io.emit("chat:message", {
            id:         data.id || `msg_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
            pseudo:     sanitize(data.pseudo, 50),
            content,
            created_at: new Date().toISOString()
        });
    });

    socket.on("chat:typing", (data) => {
        if (data && typeof data.pseudo === "string") {
            socket.broadcast.emit("chat:userTyping", {
                pseudo:   sanitize(data.pseudo, 50),
                isTyping: Boolean(data.isTyping)
            });
        }
    });

    // Invalidation cache sanctions après action admin
    socket.on("admin:invalidate", (data) => {
        if (data?.authId) sanctionCache.delete(data.authId);
    });

    socket.on("disconnect", () => {
        onlineUsers--;
        const user = connectedSockets.get(socket.id);
        if (user) {
            io.emit("chat:message", {
                id:         `sys_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
                pseudo:     "SYSTEM",
                content:    `${user.pseudo} a quitté le chat`,
                created_at: new Date().toISOString(),
                isSystem:   true
            });
            connectedSockets.delete(socket.id);
        }
        chatRateMap.delete(socket.id);
        io.emit("users", onlineUsers);
    });
});

// ==================== HTTP ROUTES ====================
app.get("/favicon.ico", (req, res) => res.status(204).end());
app.get("/health",      (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));
app.get("/api/status",  (req, res) => res.json({ status: "online", onlineUsers, timestamp: new Date().toISOString() }));
app.get("/api/csrf-nonce", (req, res) => res.json({ nonce: generateCsrfNonce() }));

app.get("/api/stats/dashboard", requireAuth, statsLimiter, (req, res) => {
    res.json({ ...statsCache, timestamp: new Date().toISOString() });
});

app.post("/verify-captcha", captchaLimiter, async (req, res) => {
    const { token, csrfNonce } = req.body;
    if (!consumeCsrfNonce(csrfNonce)) return res.status(403).json({ success: false, message: "CSRF invalide" });
    if (!token || typeof token !== "string") return res.status(400).json({ success: false, message: "Token manquant" });
    if (!TURNSTILE_SECRET) return res.status(500).json({ success: false, message: "Config incomplète" });
    try {
        const form = new URLSearchParams();
        form.append("secret", TURNSTILE_SECRET); form.append("response", token); form.append("remoteip", req.ip);
        const cf = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form.toString()
        });
        const cfData = await cf.json();
        if (!cfData.success) { log("WARN", "captcha_fail", { ip: req.ip }); return res.status(400).json({ success: false, message: "Captcha invalide" }); }
        res.json({ success: true });
    } catch (_) { res.status(500).json({ success: false, message: "Erreur captcha" }); }
});

app.post("/validate-register", registerLimiter, (req, res) => {
    const { email, password, csrfNonce } = req.body;
    if (!consumeCsrfNonce(csrfNonce)) return res.status(403).json({ success: false, message: "CSRF invalide" });
    if (!validateEmail(email))         return res.status(400).json({ success: false, message: "Email invalide" });
    if (!validatePassword(password))   return res.status(400).json({ success: false, message: "Mot de passe trop faible (8+ car, 1 maj, 1 chiffre, 1 symbole)" });
    res.json({ success: true });
});

app.post("/validate-login", loginLimiter, (req, res) => {
    const { email, csrfNonce } = req.body;
    if (!consumeCsrfNonce(csrfNonce)) return res.status(403).json({ success: false, message: "CSRF invalide" });
    if (!validateEmail(email))         return res.status(400).json({ success: false, message: "Identifiants incorrects" });
    res.json({ success: true });
});

app.use((req, res)            => res.status(404).json({ error: "Route non trouvée" }));
app.use((err, req, res, _next) => { log("ERROR", "unhandled", { msg: err.message }); res.status(500).json({ error: "Erreur interne" }); });

server.listen(PORT, () => log("INFO", "server_start", { port: PORT }));
