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

const app    = express();
const server = http.createServer(app);
const io     = socketIo(server, {
    cors: { origin: "*", methods: ["GET", "POST"], credentials: true }
});

// ==================== CONFIGURATION ====================
const PORT             = process.env.PORT || 3000;
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || ""; // variable d'env sur Render
const ALLOWED_ORIGINS  = (process.env.ALLOWED_ORIGINS || "*").split(",").map(s => s.trim());

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
    // Affichage console
    console.log(`[${level}] ${event}`, details);
    // Écriture fichier (non-bloquant best-effort)
    try { fs.appendFileSync(LOG_FILE, entry + "\n"); } catch (_) {}
}

// ==================== HELMET — EN-TÊTES DE SÉCURITÉ ====================
app.use(helmet({
    contentSecurityPolicy: false,   // géré côté HTML via <meta>
    hsts: {
        maxAge:            31536000,
        includeSubDomains: true,
        preload:           true
    },
    frameguard:     { action: "deny" },
    noSniff:        true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));

app.disable("x-powered-by");

// ==================== CORS ====================
const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes("*") || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            log("WARN", "cors_blocked", { origin });
            callback(new Error("Not allowed by CORS"));
        }
    },
    methods:        ["GET", "POST", "OPTIONS"],
    credentials:    true,
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"]
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ==================== BODY PARSING ====================
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// ==================== LOGGING DES REQUÊTES ====================
app.use((req, res, next) => {
    log("INFO", "request", { method: req.method, path: req.path, ip: req.ip });
    next();
});

// ==================== RATE LIMITERS ====================

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min
    max: 200,
    standardHeaders: true,
    legacyHeaders:   false,
    handler: (req, res) => {
        log("WARN", "rate_limit_global", { ip: req.ip, path: req.path });
        res.status(429).json({ error: "Trop de requêtes. Réessayez plus tard." });
    }
});

// /verify-captcha : max 10 / minute
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

// /validate-register : max 3 / heure
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

// /validate-login : max 5 / 15 min
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

app.use(globalLimiter);

// ==================== VALIDATION ====================
// Mot de passe : 8 chars min, 1 majuscule, 1 chiffre, 1 caractère spécial
const PASSWORD_REGEX = /^(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/;

function validateEmail(email) {
    if (!email || typeof email !== "string") return false;
    return validator.isEmail(email.trim());
}

function validatePassword(password) {
    if (!password || typeof password !== "string") return false;
    return PASSWORD_REGEX.test(password);
}

// ==================== CSRF — NONCES À USAGE UNIQUE ====================
// Le frontend appelle GET /api/csrf-nonce pour obtenir un nonce,
// puis le renvoie dans le body de /verify-captcha et /validate-register.
// Chaque nonce est valide 5 minutes et consommable une seule fois.
const csrfNonces = new Map(); // Map<nonce, { expiresAt: number }>

function generateCsrfNonce() {
    const nonce = crypto.randomBytes(32).toString("hex");
    csrfNonces.set(nonce, { expiresAt: Date.now() + 5 * 60 * 1000 });
    return nonce;
}

function consumeCsrfNonce(nonce) {
    if (!nonce || !csrfNonces.has(nonce)) return false;
    const entry = csrfNonces.get(nonce);
    csrfNonces.delete(nonce); // usage unique — supprimé immédiatement
    return Date.now() < entry.expiresAt;
}

// Nettoyage périodique des nonces expirés (toutes les 10 min)
setInterval(() => {
    const now = Date.now();
    for (const [key, val] of csrfNonces) {
        if (now > val.expiresAt) csrfNonces.delete(key);
    }
}, 10 * 60 * 1000);

// ==================== ÉTAT DU SERVEUR ====================
let users = 0;
let chatMessages = [];
const MAX_MESSAGES   = 100;
const connectedUsers = new Map();

// ==================== SOCKET.IO ====================
io.on("connection", (socket) => {
    users++;
    log("INFO", "socket_connect", { socketId: socket.id, total: users });
    io.emit("users", users);
    socket.emit("chat:history", chatMessages);

    socket.on("chat:join", (data) => {
        if (data && typeof data.pseudo === "string" && data.pseudo.trim().length > 0) {
            const pseudo = data.pseudo.trim().substring(0, 50);
            connectedUsers.set(socket.id, { pseudo, socketId: socket.id });
            log("INFO", "chat_join", { pseudo });
            const msg = {
                id: `msg_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
                pseudo: "SYSTEM",
                content: `${pseudo} a rejoint le chat`,
                created_at: new Date().toISOString(),
                isSystem: true
            };
            chatMessages.push(msg);
            if (chatMessages.length > MAX_MESSAGES) chatMessages.shift();
            io.emit("chat:message", msg);
        }
    });

    socket.on("chat:send", (data) => {
        if (!data.pseudo || typeof data.pseudo !== "string" ||
            !data.content || typeof data.content !== "string") {
            socket.emit("chat:error", { message: "Pseudo et contenu requis" });
            return;
        }
        const content = data.content.trim();
        if (content.length === 0) {
            socket.emit("chat:error", { message: "Le message ne peut pas être vide" });
            return;
        }
        if (content.length > 1000) {
            socket.emit("chat:error", { message: "Message trop long (max 1000 caractères)" });
            return;
        }
        const message = {
            id: data.id || `msg_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
            pseudo: String(data.pseudo).substring(0, 50),
            content,
            created_at: new Date().toISOString()
        };
        chatMessages.push(message);
        if (chatMessages.length > MAX_MESSAGES) chatMessages.shift();
        io.emit("chat:message", message);
    });

    socket.on("chat:typing", (data) => {
        if (data && typeof data.pseudo === "string") {
            socket.broadcast.emit("chat:userTyping", {
                pseudo:   String(data.pseudo).substring(0, 50),
                isTyping: Boolean(data.isTyping)
            });
        }
    });

    socket.on("disconnect", () => {
        users--;
        const user = connectedUsers.get(socket.id);
        if (user) {
            log("INFO", "socket_disconnect", { pseudo: user.pseudo, total: users });
            const msg = {
                id: `msg_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
                pseudo: "SYSTEM",
                content: `${user.pseudo} a quitté le chat`,
                created_at: new Date().toISOString(),
                isSystem: true
            };
            chatMessages.push(msg);
            if (chatMessages.length > MAX_MESSAGES) chatMessages.shift();
            io.emit("chat:message", msg);
            connectedUsers.delete(socket.id);
        }
        io.emit("users", users);
    });
});

// ==================== ROUTES ====================

app.get("/favicon.ico", (req, res) => res.status(204).end());

app.get("/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ---- CSRF nonce — appelé par le frontend avant toute opération sensible ----
app.get("/api/csrf-nonce", (req, res) => {
    const nonce = generateCsrfNonce();
    res.json({ nonce });
});

// ---- Vérification captcha Turnstile (avec validation réelle Cloudflare) ----
app.post("/verify-captcha", captchaLimiter, async (req, res) => {
    const { token, csrfNonce } = req.body;

    if (!consumeCsrfNonce(csrfNonce)) {
        log("WARN", "csrf_invalid_captcha", { ip: req.ip });
        return res.status(403).json({ success: false, message: "Requête invalide (CSRF)" });
    }

    if (!token || typeof token !== "string") {
        log("WARN", "captcha_token_missing", { ip: req.ip });
        return res.status(400).json({ success: false, message: "Token captcha manquant" });
    }

    if (!TURNSTILE_SECRET) {
        log("ERROR", "captcha_secret_not_configured");
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
            log("WARN", "captcha_invalid", { ip: req.ip, errors: cfData["error-codes"] });
            return res.status(400).json({ success: false, message: "Captcha invalide. Veuillez réessayer." });
        }

        log("INFO", "captcha_ok", { ip: req.ip });
        res.json({ success: true });

    } catch (err) {
        log("ERROR", "captcha_fetch_failed", { error: err.message });
        res.status(500).json({ success: false, message: "Erreur lors de la vérification du captcha" });
    }
});

// ---- Validation côté serveur avant inscription Supabase ----
app.post("/validate-register", registerLimiter, (req, res) => {
    const { email, password, csrfNonce } = req.body;

    if (!consumeCsrfNonce(csrfNonce)) {
        log("WARN", "csrf_invalid_register", { ip: req.ip });
        return res.status(403).json({ success: false, message: "Requête invalide (CSRF)" });
    }
    if (!validateEmail(email)) {
        log("WARN", "register_bad_email", { ip: req.ip });
        return res.status(400).json({ success: false, message: "Email invalide" });
    }
    if (!validatePassword(password)) {
        log("WARN", "register_weak_password", { ip: req.ip });
        return res.status(400).json({
            success: false,
            message: "Mot de passe insuffisant (8 min, 1 majuscule, 1 chiffre, 1 symbole)"
        });
    }

    log("INFO", "register_validated", { ip: req.ip });
    res.json({ success: true });
});

// ---- Pré-validation login (rate limiting + format email) ----
app.post("/validate-login", loginLimiter, (req, res) => {
    const { email } = req.body;
    if (!validateEmail(email)) {
        log("WARN", "login_bad_email", { ip: req.ip });
        // Message volontairement générique
        return res.status(400).json({ success: false, message: "Identifiants incorrects" });
    }
    log("INFO", "login_attempt", { ip: req.ip });
    res.json({ success: true });
});

// ---- Routes API existantes ----
app.get("/api/status", (req, res) => {
    res.json({ status: "online", onlineUsers: users, totalMessages: chatMessages.length, timestamp: new Date().toISOString() });
});

app.get("/api/chat/messages", (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    res.json({ messages: chatMessages.slice(-limit), total: chatMessages.slice(-limit).length, timestamp: new Date().toISOString() });
});

app.get("/api/chat/stats", (req, res) => {
    res.json({
        totalMessages: chatMessages.length,
        onlineUsers:   users,
        connectedUsers: Array.from(connectedUsers.values()).map(u => u.pseudo),
        timestamp: new Date().toISOString()
    });
});

app.get("/api/stats/dashboard", (req, res) => {
    res.json({ indexedLines: "1.9B", totalSearches: "4.2M", registeredUsers: "106.6K", timestamp: new Date().toISOString() });
});

app.get("/", (req, res) => res.redirect("/health"));

// 404
app.use((req, res) => {
    log("WARN", "not_found", { method: req.method, path: req.path, ip: req.ip });
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
    console.log("\n" + "=".repeat(60));
    console.log("🚀 SERVEUR RAPACE DÉMARRÉ");
    console.log(`📍 Port          : ${PORT}`);
    console.log(`🔒 HSTS          : activé (1 an)`);
    console.log(`🛡  Rate limiting : /login(5/15min) /register(3/h) /captcha(10/min)`);
    console.log(`✅ Turnstile     : vérification réelle Cloudflare`);
    console.log(`🔑 CSRF nonces   : usage unique, expiration 5min`);
    console.log(`📋 Logs          : ${LOG_FILE}`);
    console.log("=".repeat(60) + "\n");
});
