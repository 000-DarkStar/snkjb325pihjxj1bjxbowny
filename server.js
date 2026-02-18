const express    = require("express");
const http       = require("http");
const socketIo   = require("socket.io");
const cors       = require("cors");
const rateLimit  = require("express-rate-limit");
const helmet     = require("helmet");
const validator  = require("validator");
const crypto     = require("crypto");
const fs         = require("fs");
const path       = require("path");
const { createClient } = require("@supabase/supabase-js");

const app    = express();
const server = http.createServer(app);

// ==================== CONFIGURATION ====================
const PORT             = process.env.PORT || 3000;
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";
const ALLOWED_ORIGINS  = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);

// Supabase service client (côté serveur uniquement — jamais exposé au frontend)
const SUPABASE_URL          = process.env.SUPABASE_URL || "";
const SUPABASE_SERVICE_KEY  = process.env.SUPABASE_SERVICE_KEY || "";
const supabaseAdmin = (SUPABASE_URL && SUPABASE_SERVICE_KEY)
    ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } })
    : null;

// ==================== LOGGING SÉCURITÉ ====================
const LOG_DIR  = path.join(__dirname, "logs");
const LOG_FILE = path.join(LOG_DIR, "security.log");

if (!fs.existsSync(LOG_DIR)) {
    try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (_) {}
}

function log(level, event, details = {}) {
    const entry = JSON.stringify({
        timestamp: new Date().toISOString(),
        level,
        event,
        ...details
    });
    // Pas de console.log en production pour ne pas exposer les IPs/events dans Render logs
    if (process.env.NODE_ENV !== "production") {
        process.stdout.write(`[${level}] ${event}\n`);
    }
    try { fs.appendFileSync(LOG_FILE, entry + "\n"); } catch (_) {}
}

// ==================== HELMET ====================
app.use(helmet({
    contentSecurityPolicy: false,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard:     { action: "deny" },
    noSniff:        true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));

app.disable("x-powered-by");

// ==================== CORS ====================
// Refuser toutes les origines sauf celles whitelistées
const corsOptions = {
    origin: (origin, callback) => {
        // Pas d'origin = requête serveur à serveur (ex: health checks) → OK
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
            return callback(null, true);
        }
        log("WARN", "cors_blocked", { origin });
        callback(new Error("Not allowed by CORS"));
    },
    methods:        ["GET", "POST", "OPTIONS"],
    credentials:    true,
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"]
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// Socket.IO avec les mêmes origines whitelistées
const io = socketIo(server, {
    cors: {
        origin: (origin, callback) => {
            if (!origin) return callback(null, true);
            if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
                return callback(null, true);
            }
            callback(new Error("Not allowed"));
        },
        methods:     ["GET", "POST"],
        credentials: true
    }
});

// ==================== BODY PARSING ====================
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// ==================== RATE LIMITERS ====================
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders:   false,
    handler: (req, res) => {
        log("WARN", "rate_limit_global", { ip: req.ip, path: req.path });
        res.status(429).json({ error: "Trop de requêtes. Réessayez plus tard." });
    }
});

const captchaLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders:   false,
    handler: (req, res) => {
        log("WARN", "rate_limit_captcha", { ip: req.ip });
        res.status(429).json({ error: "Trop de tentatives de vérification captcha." });
    }
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders:   false,
    handler: (req, res) => {
        log("WARN", "rate_limit_register", { ip: req.ip });
        res.status(429).json({ error: "Trop de tentatives d'inscription. Réessayez dans 1 heure." });
    }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders:   false,
    handler: (req, res) => {
        log("WARN", "rate_limit_login", { ip: req.ip });
        res.status(429).json({ error: "Trop de tentatives de connexion. Réessayez dans 15 minutes." });
    }
});

const statsLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders:   false,
    handler: (req, res) => {
        res.status(429).json({ error: "Trop de requêtes." });
    }
});

app.use(globalLimiter);

// ==================== MIDDLEWARE JWT SUPABASE ====================
// Vérifie que la requête vient d'un user connecté via Supabase
async function requireAuth(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Non authentifié" });
    }
    const token = authHeader.slice(7);
    if (!supabaseAdmin) {
        // Si Supabase pas configuré côté serveur, on laisse passer (dégradé)
        return next();
    }
    try {
        const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
        if (error || !user) {
            return res.status(401).json({ error: "Token invalide ou expiré" });
        }
        req.user = user;
        next();
    } catch (_) {
        return res.status(401).json({ error: "Erreur d'authentification" });
    }
}

// ==================== VALIDATION ====================
const PASSWORD_REGEX = /^(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/;

function validateEmail(email) {
    if (!email || typeof email !== "string") return false;
    return validator.isEmail(email.trim());
}

function validatePassword(password) {
    if (!password || typeof password !== "string") return false;
    return PASSWORD_REGEX.test(password);
}

// Sanitize texte : supprime balises HTML
function sanitizeText(str, maxLen = 1000) {
    if (!str || typeof str !== "string") return "";
    return validator.escape(str.trim()).substring(0, maxLen);
}

// ==================== CSRF NONCES ====================
const csrfNonces = new Map();

function generateCsrfNonce() {
    const nonce = crypto.randomBytes(32).toString("hex");
    csrfNonces.set(nonce, { expiresAt: Date.now() + 5 * 60 * 1000 });
    return nonce;
}

function consumeCsrfNonce(nonce) {
    if (!nonce || !csrfNonces.has(nonce)) return false;
    const entry = csrfNonces.get(nonce);
    csrfNonces.delete(nonce);
    return Date.now() < entry.expiresAt;
}

setInterval(() => {
    const now = Date.now();
    for (const [key, val] of csrfNonces) {
        if (now > val.expiresAt) csrfNonces.delete(key);
    }
}, 10 * 60 * 1000);

// ==================== ÉTAT SOCKET ====================
let onlineUsers = 0;
// chatMessages n'est plus gardé en mémoire — le chat passe par Supabase Realtime
// On garde juste le nombre d'users connectés
const connectedUsers = new Map(); // socketId → { pseudo }

// Cache stats dashboard (mis à jour toutes les 5 min via Supabase)
let statsCache = {
    indexedLines:    "1.9B",
    totalSearches:   0,
    registeredUsers: 0,
    updatedAt:       0
};
const STATS_TTL = 5 * 60 * 1000; // 5 minutes

async function refreshStatsCache() {
    if (!supabaseAdmin) return;
    try {
        // Nombre de users
        const { count: userCount } = await supabaseAdmin
            .from("users")
            .select("*", { count: "exact", head: true });

        // Nombre de recherches
        const { count: searchCount } = await supabaseAdmin
            .from("search_logs")
            .select("*", { count: "exact", head: true });

        statsCache = {
            indexedLines:    "1.9B", // donnée statique business
            totalSearches:   searchCount ?? 0,
            registeredUsers: userCount ?? 0,
            updatedAt:       Date.now()
        };
    } catch (_) {
        // Garde le cache précédent si erreur
    }
}

// Refresh au démarrage puis toutes les 5 min
refreshStatsCache();
setInterval(refreshStatsCache, STATS_TTL);

// ==================== SOCKET.IO ====================
io.on("connection", (socket) => {
    onlineUsers++;
    io.emit("users", onlineUsers);

    socket.on("chat:join", (data) => {
        if (data && typeof data.pseudo === "string" && data.pseudo.trim().length > 0) {
            const pseudo = sanitizeText(data.pseudo, 50);
            connectedUsers.set(socket.id, { pseudo });
            log("INFO", "chat_join", { pseudo });
            // Message système diffusé
            io.emit("chat:message", {
                id:         `sys_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
                pseudo:     "SYSTEM",
                content:    `${pseudo} a rejoint le chat`,
                created_at: new Date().toISOString(),
                isSystem:   true
            });
        }
    });

    socket.on("chat:send", (data) => {
        if (!data || typeof data.pseudo !== "string" || typeof data.content !== "string") {
            socket.emit("chat:error", { message: "Données invalides" });
            return;
        }
        const content = sanitizeText(data.content, 1000);
        if (content.length === 0) {
            socket.emit("chat:error", { message: "Message vide" });
            return;
        }
        const message = {
            id:         data.id || `msg_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
            pseudo:     sanitizeText(data.pseudo, 50),
            content,
            created_at: new Date().toISOString()
        };
        io.emit("chat:message", message);
    });

    socket.on("chat:typing", (data) => {
        if (data && typeof data.pseudo === "string") {
            socket.broadcast.emit("chat:userTyping", {
                pseudo:   sanitizeText(data.pseudo, 50),
                isTyping: Boolean(data.isTyping)
            });
        }
    });

    socket.on("disconnect", () => {
        onlineUsers--;
        const user = connectedUsers.get(socket.id);
        if (user) {
            log("INFO", "socket_disconnect", { pseudo: user.pseudo });
            io.emit("chat:message", {
                id:         `sys_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
                pseudo:     "SYSTEM",
                content:    `${user.pseudo} a quitté le chat`,
                created_at: new Date().toISOString(),
                isSystem:   true
            });
            connectedUsers.delete(socket.id);
        }
        io.emit("users", onlineUsers);
    });
});

// ==================== ROUTES ====================

app.get("/favicon.ico", (req, res) => res.status(204).end());

app.get("/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// CSRF nonce
app.get("/api/csrf-nonce", (req, res) => {
    res.json({ nonce: generateCsrfNonce() });
});

// Stats dashboard — authentification requise + cache Supabase
app.get("/api/stats/dashboard", requireAuth, statsLimiter, (req, res) => {
    res.json({
        indexedLines:    statsCache.indexedLines,
        totalSearches:   statsCache.totalSearches,
        registeredUsers: statsCache.registeredUsers,
        timestamp:       new Date().toISOString()
    });
});

// Status serveur — public mais limité
app.get("/api/status", (req, res) => {
    res.json({
        status:       "online",
        onlineUsers,
        timestamp:    new Date().toISOString()
    });
});

// Vérification captcha
app.post("/verify-captcha", captchaLimiter, async (req, res) => {
    const { token, csrfNonce } = req.body;

    if (!consumeCsrfNonce(csrfNonce)) {
        log("WARN", "csrf_invalid_captcha", { ip: req.ip });
        return res.status(403).json({ success: false, message: "Requête invalide (CSRF)" });
    }
    if (!token || typeof token !== "string") {
        return res.status(400).json({ success: false, message: "Token captcha manquant" });
    }
    if (!TURNSTILE_SECRET) {
        return res.status(500).json({ success: false, message: "Configuration serveur incomplète" });
    }

    try {
        const formData = new URLSearchParams();
        formData.append("secret",   TURNSTILE_SECRET);
        formData.append("response", token);
        formData.append("remoteip", req.ip);

        const cfRes  = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method:  "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body:    formData.toString()
        });
        const cfData = await cfRes.json();

        if (!cfData.success) {
            log("WARN", "captcha_invalid", { ip: req.ip });
            return res.status(400).json({ success: false, message: "Captcha invalide. Veuillez réessayer." });
        }

        res.json({ success: true });
    } catch (_) {
        res.status(500).json({ success: false, message: "Erreur lors de la vérification du captcha" });
    }
});

// Validation inscription
app.post("/validate-register", registerLimiter, (req, res) => {
    const { email, password, csrfNonce } = req.body;

    if (!consumeCsrfNonce(csrfNonce)) {
        log("WARN", "csrf_invalid_register", { ip: req.ip });
        return res.status(403).json({ success: false, message: "Requête invalide (CSRF)" });
    }
    if (!validateEmail(email)) {
        return res.status(400).json({ success: false, message: "Email invalide" });
    }
    if (!validatePassword(password)) {
        return res.status(400).json({
            success: false,
            message: "Mot de passe insuffisant (8 min, 1 majuscule, 1 chiffre, 1 symbole)"
        });
    }

    log("INFO", "register_validated", { ip: req.ip });
    res.json({ success: true });
});

// Pré-validation login
app.post("/validate-login", loginLimiter, (req, res) => {
    const { email, csrfNonce } = req.body;
    if (!consumeCsrfNonce(csrfNonce)) {
        log("WARN", "csrf_invalid_login", { ip: req.ip });
        return res.status(403).json({ success: false, message: "Requête invalide (CSRF)" });
    }
    if (!validateEmail(email)) {
        return res.status(400).json({ success: false, message: "Identifiants incorrects" });
    }
    res.json({ success: true });
});

// 404
app.use((req, res) => {
    res.status(404).json({ error: "Route non trouvée" });
});

// Erreur globale
app.use((err, req, res, _next) => {
    log("ERROR", "unhandled_error", { message: err.message });
    res.status(500).json({ error: "Erreur interne du serveur" });
});

// ==================== DÉMARRAGE ====================
server.listen(PORT, () => {
    log("INFO", "server_start", { port: PORT });
});
