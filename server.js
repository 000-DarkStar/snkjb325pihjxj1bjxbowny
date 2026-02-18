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
// Trust proxy — Render utilise X-Forwarded-For
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

// Admin UIDs — seuls ces comptes bypass la maintenance et accèdent aux routes admin
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
        methods:     ["GET", "POST"],
        credentials: true
    },
    // Limite la taille des paquets Socket.IO
    maxHttpBufferSize: 1e4  // 10 KB max par message socket
});

// ==================== BODY PARSING ====================
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

// ==================== RATE LIMITERS ====================
const mkLimiter = (windowMs, max, msg) => rateLimit({
    windowMs, max,
    standardHeaders: true,
    legacyHeaders:   false,
    // Clé par IP — on n'expose pas d'infos sensibles
    keyGenerator: (req) => req.ip,
    handler: (req, res) => {
        log("WARN", "rate_limit", { ip: req.ip, path: req.path });
        res.status(429).json({ error: msg });
    }
});

// Global — 300 req/15 min par IP
app.use(mkLimiter(15 * 60 * 1000, 300, "Trop de requêtes. Réessayez plus tard."));

const captchaLimiter    = mkLimiter(60 * 1000,       10, "Trop de tentatives captcha.");
const registerLimiter   = mkLimiter(60 * 60 * 1000,   3, "Trop d'inscriptions. Réessayez dans 1h.");
const loginLimiter      = mkLimiter(15 * 60 * 1000,   5, "Trop de tentatives. Réessayez dans 15 min.");
const statsLimiter      = mkLimiter(60 * 1000,        30, "Trop de requêtes stats.");
const maintenanceLimiter = mkLimiter(60 * 1000,       60, "Trop de requêtes maintenance.");

// ==================== JWT MIDDLEWARE ====================
async function requireAuth(req, res, next) {
    const auth = req.headers["authorization"];
    if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Non authentifié" });
    const token = auth.slice(7);
    if (!supabaseAdmin) return res.status(503).json({ error: "Service indisponible" });
    try {
        const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: "Token invalide" });
        req.user = user;
        next();
    } catch (_) { res.status(401).json({ error: "Erreur auth" }); }
}

// Admin uniquement
async function requireAdmin(req, res, next) {
    await requireAuth(req, res, async () => {
        if (!ADMIN_UIDS.has(req.user?.id)) {
            log("WARN", "admin_access_denied", { uid: req.user?.id, ip: req.ip, path: req.path });
            return res.status(403).json({ error: "Accès refusé" });
        }
        next();
    });
}

// ==================== VALIDATION & SANITIZE ====================
const PWD_REGEX = /^(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,72}$/;
const validateEmail    = e => !!(e && typeof e === "string" && validator.isEmail(e.trim()) && e.length <= 254);
const validatePassword = p => !!(p && typeof p === "string" && PWD_REGEX.test(p) && p.length <= 72);
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
// Nettoyage toutes les 10 minutes
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of csrfNonces) if (now > v.expiresAt) csrfNonces.delete(k);
}, 10 * 60 * 1000);

// ==================== MAINTENANCE CACHE ====================
// TTL court (15s) pour être réactif sans surcharger Supabase
let _maintenanceCache = null;
let _maintenanceCacheTs = 0;
const MAINTENANCE_TTL = 15 * 1000;

async function getMaintenanceState() {
    // Retourne le cache si récent
    if (_maintenanceCache !== null && Date.now() - _maintenanceCacheTs < MAINTENANCE_TTL) {
        return _maintenanceCache;
    }
    if (!supabaseAdmin) return { active: false };
    try {
        const { data, error } = await supabaseAdmin
            .from("system_settings")
            .select("value")
            .eq("key", "maintenance")
            .single();
        if (error || !data) {
            _maintenanceCache = { active: false };
        } else {
            const val = typeof data.value === "string" ? JSON.parse(data.value) : data.value;
            _maintenanceCache = val || { active: false };
        }
    } catch (_) {
        _maintenanceCache = { active: false };
    }
    _maintenanceCacheTs = Date.now();
    return _maintenanceCache;
}

// Invalide le cache immédiatement (appelé après toggle depuis l'admin)
function invalidateMaintenanceCache() {
    _maintenanceCache = null;
    _maintenanceCacheTs = 0;
}

// ==================== MAINTENANCE MIDDLEWARE ====================
// Routes exclues : health, status, csrf-nonce, et la route maintenance elle-même
const MAINTENANCE_WHITELIST = new Set([
    "/health",
    "/api/status",
    "/api/csrf-nonce",
    "/api/maintenance",
    "/favicon.ico"
]);

async function maintenanceGuard(req, res, next) {
    // Routes toujours accessibles
    if (MAINTENANCE_WHITELIST.has(req.path)) return next();

    const state = await getMaintenanceState();
    if (!state?.active) return next();

    // Maintenance active — vérifie si l'utilisateur est admin
    const auth = req.headers["authorization"];
    if (auth?.startsWith("Bearer ") && supabaseAdmin) {
        try {
            const { data: { user } } = await supabaseAdmin.auth.getUser(auth.slice(7));
            if (user && ADMIN_UIDS.has(user.id)) {
                // Admin → laisse passer
                return next();
            }
        } catch (_) {}
    }

    // Pas admin → bloque
    log("INFO", "maintenance_blocked", { ip: req.ip, path: req.path });
    res.status(503).json({
        error:        "maintenance",
        message:      state.message || "La plateforme est en maintenance. Réessayez bientôt.",
        end_time:     state.end_time || null,
        progress:     state.progress ?? null,
        retry_after:  60
    });
}

// Applique le guard à toutes les routes API
app.use(maintenanceGuard);

// ==================== STATS CACHE ====================
let statsCache = { indexedLines: "1.9B", totalSearches: 0, registeredUsers: 0 };

async function refreshStats() {
    if (!supabaseAdmin) return;
    try {
        const [{ count: users }, { count: searches }] = await Promise.all([
            supabaseAdmin.from("users").select("*", { count: "exact", head: true }),
            supabaseAdmin.from("search_logs").select("*", { count: "exact", head: true })
        ]);
        statsCache = {
            indexedLines:   "1.9B",
            totalSearches:  searches ?? 0,
            registeredUsers: users ?? 0
        };
    } catch (_) {}
}
refreshStats();
setInterval(refreshStats, 5 * 60 * 1000);

// ==================== SANCTION CACHE (chat) ====================
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

// ==================== SOCKET.IO ====================
let onlineUsers = 0;
const connectedSockets = new Map();
const chatRateMap      = new Map();
const CHAT_RATE_MS     = 1000;

io.on("connection", async (socket) => {
    // Vérifie la maintenance au moment de la connexion socket
    const state = await getMaintenanceState();
    if (state?.active) {
        socket.emit("maintenance", {
            message:  state.message || "Plateforme en maintenance.",
            end_time: state.end_time || null
        });
        // Coupe la connexion socket si maintenance (sauf admin)
        // On laisse la connexion ouverte pour que le client reçoive l'event
        setTimeout(() => socket.disconnect(true), 500);
        return;
    }

    onlineUsers++;
    io.emit("users", onlineUsers);

    socket.on("chat:join", (data) => {
        if (!data?.pseudo || typeof data.pseudo !== "string") return;
        const pseudo = sanitize(data.pseudo, 50);
        const authId = typeof data.authId === "string" ? data.authId.substring(0, 64) : null;
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

        // Rate limit
        const now  = Date.now();
        const last = chatRateMap.get(socket.id) || 0;
        if (now - last < CHAT_RATE_MS) {
            socket.emit("chat:error", { message: "Un message par seconde maximum." });
            return;
        }
        chatRateMap.set(socket.id, now);

        const content = sanitize(data.content, 1000);
        if (!content || content.length === 0) {
            socket.emit("chat:error", { message: "Message vide" });
            return;
        }

        // Sanctions
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

    socket.on("admin:invalidate", (data) => {
        if (data?.authId) sanctionCache.delete(data.authId);
    });

    // Quand un admin toggle la maintenance via le panel
    socket.on("admin:maintenance_toggle", async (data) => {
        const sd = connectedSockets.get(socket.id);
        if (!sd?.authId || !ADMIN_UIDS.has(sd.authId)) return;
        invalidateMaintenanceCache();
        // Broadcast à tous les clients connectés
        const newState = await getMaintenanceState();
        if (newState?.active) {
            // Déconnecter tous les non-admins
            for (const [sid, info] of connectedSockets) {
                if (!ADMIN_UIDS.has(info.authId)) {
                    const sock = io.sockets.sockets.get(sid);
                    if (sock) {
                        sock.emit("maintenance", { message: newState.message, end_time: newState.end_time });
                        setTimeout(() => sock.disconnect(true), 500);
                    }
                }
            }
        }
        log("INFO", "maintenance_toggled", { by: sd.authId, active: newState?.active });
    });

    socket.on("disconnect", () => {
        onlineUsers = Math.max(0, onlineUsers - 1);
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
        io.emit("users", Math.max(0, onlineUsers));
    });
});

// ==================== HTTP ROUTES ====================

// Routes publiques — toujours accessibles
app.get("/favicon.ico", (req, res) => res.status(204).end());

app.get("/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.get("/api/status", (req, res) => {
    res.json({ status: "online", onlineUsers, timestamp: new Date().toISOString() });
});

app.get("/api/csrf-nonce", (req, res) => {
    res.json({ nonce: generateCsrfNonce() });
});

// ── Maintenance (public) ─────────────────────────────────────────────────────
// Permet au frontend de lire l'état sans auth
app.get("/api/maintenance", maintenanceLimiter, async (req, res) => {
    try {
        const state = await getMaintenanceState();
        // On n'expose que les champs nécessaires au public
        res.json({
            active:   !!state?.active,
            message:  state?.message  || null,
            end_time: state?.end_time || null,
            progress: state?.progress ?? null,
            // Steps visibles publiquement
            steps:    Array.isArray(state?.steps) ? state.steps.map(s => ({
                name:   s.name   || "",
                desc:   s.desc   || "",
                status: ["done","inprog","todo"].includes(s.status) ? s.status : "todo"
            })) : []
        });
    } catch (_) {
        res.json({ active: false });
    }
});

// ── Maintenance (admin) — toggle, mise à jour ────────────────────────────────
app.post("/api/admin/maintenance", requireAdmin, maintenanceLimiter, async (req, res) => {
    if (!supabaseAdmin) return res.status(503).json({ error: "Service indisponible" });

    const { active, message, end_time, progress, steps } = req.body;

    // Validation basique
    if (typeof active !== "boolean") return res.status(400).json({ error: "Champ 'active' requis (boolean)" });
    if (end_time && isNaN(Date.parse(end_time))) return res.status(400).json({ error: "end_time invalide" });
    if (progress !== undefined && (typeof progress !== "number" || progress < 0 || progress > 100)) {
        return res.status(400).json({ error: "progress doit être un nombre entre 0 et 100" });
    }

    try {
        // Lire l'état actuel pour merger
        const current = await getMaintenanceState();
        const newState = {
            ...current,
            active:     Boolean(active),
            message:    typeof message === "string"  ? sanitize(message, 500) : (current?.message || ""),
            end_time:   end_time  || null,
            progress:   progress  ?? current?.progress ?? 0,
            steps:      Array.isArray(steps) ? steps.map(s => ({
                name:   sanitize(s.name  || "", 200),
                desc:   sanitize(s.desc  || "", 500),
                status: ["done","inprog","todo"].includes(s.status) ? s.status : "todo"
            })) : (current?.steps || []),
            started_at: active && !current?.started_at ? new Date().toISOString() : (current?.started_at || null),
            updated_at: new Date().toISOString()
        };

        const { error } = await supabaseAdmin
            .from("system_settings")
            .upsert({ key: "maintenance", value: newState }, { onConflict: "key" });

        if (error) throw error;

        // Invalide le cache
        invalidateMaintenanceCache();

        log("INFO", "maintenance_updated", {
            by:     req.user.id,
            active: newState.active,
            ip:     req.ip
        });

        res.json({ success: true, state: newState });
    } catch (e) {
        log("ERROR", "maintenance_update_failed", { msg: e.message });
        res.status(500).json({ error: "Erreur lors de la mise à jour" });
    }
});

// ── Stats dashboard (auth requise) ──────────────────────────────────────────
app.get("/api/stats/dashboard", requireAuth, statsLimiter, (req, res) => {
    res.json({ ...statsCache, timestamp: new Date().toISOString() });
});

// ── Captcha verify ───────────────────────────────────────────────────────────
app.post("/verify-captcha", captchaLimiter, async (req, res) => {
    const { token, csrfNonce } = req.body;
    if (!consumeCsrfNonce(csrfNonce))              return res.status(403).json({ success: false, message: "CSRF invalide" });
    if (!token || typeof token !== "string")        return res.status(400).json({ success: false, message: "Token manquant" });
    if (token.length > 2048)                        return res.status(400).json({ success: false, message: "Token invalide" });
    if (!TURNSTILE_SECRET)                          return res.status(500).json({ success: false, message: "Config incomplète" });

    try {
        const form = new URLSearchParams();
        form.append("secret", TURNSTILE_SECRET);
        form.append("response", token);
        form.append("remoteip", req.ip);

        const cf = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method:  "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body:    form.toString()
        });
        const cfData = await cf.json();
        if (!cfData.success) {
            log("WARN", "captcha_fail", { ip: req.ip, errors: cfData["error-codes"] });
            return res.status(400).json({ success: false, message: "Captcha invalide" });
        }
        res.json({ success: true });
    } catch (_) {
        res.status(500).json({ success: false, message: "Erreur captcha" });
    }
});

// ── Register validation ──────────────────────────────────────────────────────
app.post("/validate-register", registerLimiter, (req, res) => {
    const { email, password, csrfNonce } = req.body;
    if (!consumeCsrfNonce(csrfNonce))    return res.status(403).json({ success: false, message: "CSRF invalide" });
    if (!validateEmail(email))           return res.status(400).json({ success: false, message: "Email invalide" });
    if (!validatePassword(password))     return res.status(400).json({ success: false, message: "Mot de passe trop faible (8+ car, 1 maj, 1 chiffre, 1 symbole)" });
    res.json({ success: true });
});

// ── Login validation ─────────────────────────────────────────────────────────
app.post("/validate-login", loginLimiter, (req, res) => {
    const { email, csrfNonce } = req.body;
    if (!consumeCsrfNonce(csrfNonce)) return res.status(403).json({ success: false, message: "CSRF invalide" });
    if (!validateEmail(email))         return res.status(400).json({ success: false, message: "Identifiants incorrects" });
    res.json({ success: true });
});

// ==================== 404 / ERROR ====================
app.use((req, res) => {
    res.status(404).json({ error: "Route non trouvée" });
});

app.use((err, req, res, _next) => {
    log("ERROR", "unhandled", { msg: err.message, path: req.path });
    res.status(500).json({ error: "Erreur interne" });
});

server.listen(PORT, () => log("INFO", "server_start", { port: PORT }));
