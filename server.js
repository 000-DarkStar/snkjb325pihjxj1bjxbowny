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

const PORT                 = process.env.PORT || 3000;
const TURNSTILE_SECRET     = process.env.TURNSTILE_SECRET     || "0x4AAAAAACXtOAo2YMkszq-RYglD_O_URx8";
const SUPABASE_URL         = process.env.SUPABASE_URL         || "https://ohmkqlouiepzkbyztnsm.supabase.co";
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9obWtxbG91aWVwemtieXp0bnNtIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2OTI2ODYyMywiZXhwIjoyMDg0ODQ0NjIzfQ.Z3BNfmfoWAO1ocgCJBadxfKF_X54fF9KZQfVn0woDes";
const SEEKNOW_API_KEY      = process.env.SEEKNOW_API_KEY      || "seek-523cdcf15695be897f9f95b4ff4180ccad7a5802269de1c4";
const WEBHOOK_URL          = process.env.WEBHOOK_URL          || "https://ptb.discord.com/api/webhooks/1473486621973151744/1Oy02CferN_JUUkkxOLHJSPxNVVst-mgGWE51KjOBJfzYZzh32HTahznN5hfdFEEBpqo";
const ALLOWED_ORIGINS = ["https://rapace.pages.dev", "https://www.rapace.pages.dev"];
    .split(",").map(s => s.trim()).filter(Boolean);

const supabaseAdmin = (SUPABASE_URL && SUPABASE_SERVICE_KEY && !SUPABASE_SERVICE_KEY.includes("ICI"))
    ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } })
    : null;

const ADMIN_UIDS = new Set([
    "5a819614-acac-4c54-a529-d15da447a47a",
    "d834eeb8-7eb5-4c61-a46e-e3c6d7fcadae"
]);

const VALID_PLANS = new Set(["free", "premium", "unlimited", "admin", "moderator"]);

const LOG_DIR  = path.join(__dirname, "logs");
const LOG_FILE = path.join(LOG_DIR, "security.log");
if (!fs.existsSync(LOG_DIR)) { try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (_) {} }
function log(level, event, details = {}) {
    const entry = JSON.stringify({ timestamp: new Date().toISOString(), level, event, ...details });
    if (process.env.NODE_ENV !== "production") process.stdout.write(`[${level}] ${event} ${JSON.stringify(details)}\n`);
    try { fs.appendFileSync(LOG_FILE, entry + "\n"); } catch (_) {}
}

app.use(helmet({
    contentSecurityPolicy: false,
    hsts:           { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard:     { action: "deny" },
    noSniff:        true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));
app.disable("x-powered-by");

const normalizedOrigins = ALLOWED_ORIGINS.map(o => {
    if (/^https?:\/\//.test(o)) return o;
    return `https://${o}`;
});

const corsOptions = {
    origin: (origin, cb) => {
        if (!origin) return cb(null, true);
        if (!normalizedOrigins.length || normalizedOrigins.includes(origin)) return cb(null, true);
        log("WARN", "cors_blocked", { origin });
        cb(new Error("Not allowed by CORS"));
    },
    methods:        ["GET", "POST", "DELETE", "OPTIONS"],
    credentials:    true,
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"]
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

const io = socketIo(server, {
    cors: {
        origin: (origin, cb) => {
            if (!origin) return cb(null, true);
            if (!normalizedOrigins.length || normalizedOrigins.includes(origin)) return cb(null, true);
            cb(new Error("Not allowed"));
        },
        methods: ["GET", "POST"], credentials: true
    },
    maxHttpBufferSize: 1e4
});

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

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
const searchLimiter      = mkLimiter(60 * 1000,       20, "Trop de requêtes de recherche.");
const adminLimiter       = mkLimiter(60 * 1000,       60, "Trop de requêtes admin.");
const historyLimiter     = mkLimiter(60 * 1000,       30, "Trop de requêtes history.");

async function requireAuth(req, res, next) {
    const auth = req.headers["authorization"];
    if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Non authentifié" });
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

const PWD_REGEX        = /^(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,72}$/;
const validateEmail    = e => !!(e && typeof e === "string" && validator.isEmail(e.trim()) && e.length <= 254);
const validatePassword = p => !!(p && typeof p === "string" && PWD_REGEX.test(p));
const sanitize         = (s, n = 1000) => typeof s === "string" ? validator.escape(s.trim()).substring(0, n) : "";

const csrfNonces = new Map();
const generateCsrfNonce = () => { const n = crypto.randomBytes(32).toString("hex"); csrfNonces.set(n, { expiresAt: Date.now() + 5 * 60 * 1000 }); return n; };
const consumeCsrfNonce = n => { if (!n || !csrfNonces.has(n)) return false; const { expiresAt } = csrfNonces.get(n); csrfNonces.delete(n); return Date.now() < expiresAt; };
setInterval(() => { const now = Date.now(); for (const [k, v] of csrfNonces) if (now > v.expiresAt) csrfNonces.delete(k); }, 10 * 60 * 1000);

let _mntCache = null, _mntTs = 0;
async function getMnt() {
    if (_mntCache !== null && Date.now() - _mntTs < 3000) return _mntCache;
    if (!supabaseAdmin) { _mntCache = { active: false }; _mntTs = Date.now(); return _mntCache; }
    try {
        const { data, error } = await supabaseAdmin
            .from("system_settings")
            .select("value")
            .eq("key", "maintenance")
            .maybeSingle();
        if (error) {
            log("WARN", "getMnt_error", { msg: error.message });
            if (_mntCache !== null) return _mntCache;
            _mntCache = { active: false };
        } else {
            const v = data?.value;
            if (!v) {
                _mntCache = { active: false };
            } else if (typeof v === "string") {
                try { _mntCache = JSON.parse(v); } catch (_) { _mntCache = { active: false }; }
            } else {
                _mntCache = v;
            }
        }
    } catch (e) {
        log("ERROR", "getMnt_catch", { msg: e.message });
        if (_mntCache !== null) return _mntCache;
        _mntCache = { active: false };
    }
    _mntTs = Date.now();
    return _mntCache;
}
function invalidateMnt() { _mntCache = null; _mntTs = 0; }

const MNT_WHITELIST = new Set([
    "/health", "/api/status", "/api/csrf-nonce",
    "/api/maintenance", "/api/admin/maintenance",
    "/api/log-event", "/favicon.ico",
    "/verify-captcha", "/validate-register", "/validate-login"
]);
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
    res.status(503).json({
        error: "maintenance",
        message: st.message || "La plateforme est en maintenance.",
        end_time: st.end_time || null,
        progress: st.progress || 0,
        retry_after: 60
    });
}
app.use(maintenanceGuard);

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

const sanctionCache = new Map();
async function getSanction(authId) {
    const cached = sanctionCache.get(authId);
    if (cached && Date.now() - cached._ts < 30000) return cached;
    if (!supabaseAdmin) return { muted: false, banned: false, blockSearch: false, mutedUntil: null };
    try {
        const { data: user } = await supabaseAdmin.from("users").select("id").eq("auth_id", authId).maybeSingle();
        if (!user) return { muted: false, banned: false, blockSearch: false, mutedUntil: null };
        const { data: sanctions } = await supabaseAdmin
            .from("sanctions")
            .select("type, expires_at")
            .eq("user_id", user.id)
            .eq("active", true)
            .or(`expires_at.is.null,expires_at.gt.${new Date().toISOString()}`);
        const mute        = sanctions?.find(s => s.type === "mute");
        const ban         = sanctions?.find(s => s.type === "ban");
        const blockSearch = sanctions?.find(s => s.type === "block_search");
        const result = {
            muted:       !!mute,
            banned:      !!ban,
            blockSearch: !!blockSearch,
            mutedUntil:  mute?.expires_at ?? null,
            _ts: Date.now()
        };
        sanctionCache.set(authId, result);
        return result;
    } catch (_) { return { muted: false, banned: false, blockSearch: false, mutedUntil: null }; }
}
function invalidateSanction(authId) { if (authId) sanctionCache.delete(authId); }

const userActivities    = new Map();
const userNotifications = new Map();
const activeSessions    = new Map();
const userPreferences   = new Map();
const keyResetCooldowns = new Map();

function pushActivity(uid, entry) {
    if (!uid) return;
    const list = userActivities.get(uid) || [];
    list.unshift({ id: `act_${Date.now()}_${Math.random().toString(36).slice(2,6)}`, ...entry, created_at: new Date().toISOString() });
    if (list.length > 200) list.length = 200;
    userActivities.set(uid, list);
    if (supabaseAdmin && entry.type) {
        supabaseAdmin.from("security_logs").insert({
            user_id:            uid,
            action_type:        (entry.type || "event").substring(0, 100),
            action_description: (entry.description || "").substring(0, 300),
            ip_address:         entry.ip || null
        }).catch(() => {});
    }
}

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
        io.emit("chat:message", {
            id: `sys_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
            pseudo: "SYSTEM", content: `${pseudo} a rejoint le chat`,
            created_at: new Date().toISOString(), isSystem: true
        });
    });

    socket.on("chat:send", async (data) => {
        if (!data || typeof data.pseudo !== "string" || typeof data.content !== "string") {
            socket.emit("chat:error", { message: "Données invalides" }); return;
        }
        const now = Date.now(), last = chatRateMap.get(socket.id) || 0;
        if (now - last < 1000) { socket.emit("chat:error", { message: "Un message par seconde maximum." }); return; }
        chatRateMap.set(socket.id, now);
        const content = sanitize(data.content, 1000);
        if (!content) { socket.emit("chat:error", { message: "Message vide" }); return; }
        const sd = connectedSockets.get(socket.id);
        if (sd?.authId) {
            const s = await getSanction(sd.authId);
            if (s.banned) { socket.emit("chat:error", { message: "Votre compte est banni." }); return; }
            if (s.muted)  { socket.emit("chat:error", { message: `Vous êtes réduit au silence${s.mutedUntil ? ` jusqu'à ${new Date(s.mutedUntil).toLocaleTimeString("fr-FR")}` : ""}.` }); return; }
        }
        io.emit("chat:message", {
            id: data.id || `msg_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
            pseudo: sanitize(data.pseudo, 50), content,
            created_at: new Date().toISOString()
        });
    });

    socket.on("chat:typing", (data) => {
        if (data && typeof data.pseudo === "string")
            socket.broadcast.emit("chat:userTyping", { pseudo: sanitize(data.pseudo, 50), isTyping: Boolean(data.isTyping) });
    });

    socket.on("admin:invalidate", (data) => {
        if (data?.authId) sanctionCache.delete(data.authId);
    });

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
            io.emit("chat:message", {
                id: `sys_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
                pseudo: "SYSTEM", content: `${user.pseudo} a quitté le chat`,
                created_at: new Date().toISOString(), isSystem: true
            });
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

// ==================== MAINTENANCE PUBLIC GET ====================
app.get("/api/maintenance", maintenanceLimiter, async (req, res) => {
    try {
        const st = await getMnt();
        res.json({
            active:   !!st?.active,
            message:  st?.message || null,
            end_time: st?.end_time || null,
            progress: st?.progress ?? null,
            steps:    Array.isArray(st?.steps) ? st.steps.map(s => ({
                name:   String(s.name  || "").substring(0, 200),
                desc:   String(s.desc  || "").substring(0, 500),
                status: ["done","inprog","todo"].includes(s.status) ? s.status : "todo"
            })) : []
        });
    } catch (_) { res.json({ active: false }); }
});

// ==================== MAINTENANCE ADMIN TOGGLE ====================
// FIX: upsert avec value en JSONB — on envoie l'objet directement (pas stringifié)
async function handleAdminMaintenance(req, res) {
    if (!supabaseAdmin) return res.status(503).json({ error: "Service indisponible" });
    let { active, message, end_time, progress, steps } = req.body;

    if (typeof active === "string") active = active === "true";
    if (typeof active !== "boolean") return res.status(400).json({ error: "'active' (boolean) requis" });

    try {
        invalidateMnt();
        const cur = await getMnt();

        const newSt = {
            active: Boolean(active),
            message:    typeof message === "string" ? sanitize(message, 500) : (cur?.message || ""),
            end_time:   (end_time && typeof end_time === "string" && end_time.trim()) ? end_time.trim() : null,
            progress:   typeof progress === "number"
                            ? Math.max(0, Math.min(100, Math.round(progress)))
                            : (typeof progress === "string" && !isNaN(parseInt(progress)))
                                ? Math.max(0, Math.min(100, parseInt(progress)))
                                : (cur?.progress ?? 0),
            steps:      Array.isArray(steps)
                            ? steps.map(s => ({
                                name:   sanitize(s.name  || "", 200),
                                desc:   sanitize(s.desc  || "", 500),
                                status: ["done","inprog","todo"].includes(s.status) ? s.status : "todo"
                              }))
                            : (cur?.steps || []),
            started_at: (active && !cur?.started_at) ? new Date().toISOString() : (cur?.started_at || null),
            updated_at: new Date().toISOString()
        };

        let upsertError = null;
        const { error: e1 } = await supabaseAdmin
            .from("system_settings")
            .upsert({ key: "maintenance", value: newSt }, { onConflict: "key" });
        upsertError = e1;

        if (upsertError && upsertError.message?.includes("invalid input syntax")) {
            log("WARN", "mnt_jsonb_fallback", { msg: upsertError.message });
            const { error: e2 } = await supabaseAdmin
                .from("system_settings")
                .upsert({ key: "maintenance", value: JSON.stringify(newSt) }, { onConflict: "key" });
            upsertError = e2;
        }

        if (upsertError) {
            log("ERROR", "mnt_upsert_fail", { msg: upsertError.message, code: upsertError.code });
            throw upsertError;
        }

        invalidateMnt();

        if (active) {
            for (const [sid, info] of connectedSockets) {
                if (!ADMIN_UIDS.has(info.authId || "")) {
                    const s = io.sockets.sockets.get(sid);
                    if (s) {
                        s.emit("maintenance", { message: newSt.message, end_time: newSt.end_time });
                        setTimeout(() => s.disconnect(true), 500);
                    }
                }
            }
        }

        log("INFO", "mnt_updated", { by: req.user.id, active: newSt.active, ip: req.ip });
        res.json({ success: true, state: newSt });
    } catch (e) {
        log("ERROR", "mnt_fail", { msg: e.message, code: e.code });
        res.status(500).json({ error: "Erreur mise à jour maintenance: " + e.message });
    }
}

app.post("/api/admin/maintenance", requireAdmin, maintenanceLimiter, handleAdminMaintenance);
app.post("/api/admin/applyMaint", requireAdmin, maintenanceLimiter, handleAdminMaintenance);
app.post("/api/admin/applyMaintenance", requireAdmin, maintenanceLimiter, handleAdminMaintenance);

app.post("/api/admin/set-plan", requireAdmin, adminLimiter, async (req, res) => {
    if (!supabaseAdmin) return res.status(503).json({ error: "Service indisponible" });
    const { user_id, auth_id, plan, max_credits } = req.body;

    if (!plan || !VALID_PLANS.has(String(plan).toLowerCase()))
        return res.status(400).json({ error: "Plan invalide. Valeurs: free, premium, unlimited, admin, moderator" });
    if (!user_id && !auth_id)
        return res.status(400).json({ error: "user_id ou auth_id requis" });

    const planLower = plan.toLowerCase();
    const newMaxCredits = (max_credits != null && !isNaN(parseInt(max_credits)))
        ? parseInt(max_credits)
        : { free: 10, premium: 50, unlimited: 9999, admin: 9999, moderator: 200 }[planLower] || 10;
    const payload = { plan: planLower, max_credits: newMaxCredits, credits: newMaxCredits };

    try {
        let updated = false;
        if (auth_id) {
            const { data, error: e1 } = await supabaseAdmin.from("users").update(payload).eq("auth_id", auth_id).select("id");
            if (!e1 && data && data.length > 0) updated = true;
        }
        if (!updated && user_id) {
            const { data, error: e2 } = await supabaseAdmin.from("users").update(payload).eq("id", user_id).select("id");
            if (!e2 && data && data.length > 0) updated = true;
        }
        if (!updated) return res.status(404).json({ error: "Utilisateur introuvable ou aucune ligne mise à jour" });
        if (auth_id) invalidateSanction(auth_id);
        log("INFO", "admin_set_plan", { by: req.user.id, target: user_id || auth_id, plan: planLower, ip: req.ip });
        res.json({ success: true, plan: planLower, max_credits: payload.max_credits });
    } catch (e) {
        log("ERROR", "set_plan_fail", { msg: e.message, ip: req.ip });
        res.status(500).json({ error: "Erreur serveur: " + e.message });
    }
});

app.post("/api/admin/set-credits", requireAdmin, adminLimiter, async (req, res) => {
    if (!supabaseAdmin) return res.status(503).json({ error: "Service indisponible" });
    const { user_id, auth_id, action, amount } = req.body;

    if (!["add", "set", "set_max"].includes(action))
        return res.status(400).json({ error: "action invalide: add | set | set_max" });
    if (amount == null || isNaN(parseInt(amount)))
        return res.status(400).json({ error: "amount (nombre) requis" });
    if (!user_id && !auth_id)
        return res.status(400).json({ error: "user_id ou auth_id requis" });

    const amt = parseInt(amount);
    if (amt < 0 || amt > 99999) return res.status(400).json({ error: "Amount hors limites (0-99999)" });

    try {
        let userData = null;
        if (auth_id) {
            const { data } = await supabaseAdmin.from("users").select("id, credits, max_credits").eq("auth_id", auth_id).maybeSingle();
            userData = data;
        }
        if (!userData && user_id) {
            const { data } = await supabaseAdmin.from("users").select("id, credits, max_credits").eq("id", user_id).maybeSingle();
            userData = data;
        }
        if (!userData) return res.status(404).json({ error: "Utilisateur introuvable" });

        let payload = {}, newVal;
        if (action === "add")      { newVal = (userData.credits || 0) + amt; payload = { credits: newVal }; }
        else if (action === "set") { newVal = amt; payload = { credits: newVal }; }
        else if (action === "set_max") {
            if (amt < 1) return res.status(400).json({ error: "max_credits minimum: 1" });
            newVal = amt; payload = { max_credits: newVal };
        }

        const { data: updated, error } = await supabaseAdmin
            .from("users").update(payload).eq("id", userData.id).select("id, credits, max_credits");
        if (error) throw error;
        if (!updated || updated.length === 0) return res.status(404).json({ error: "Aucune ligne mise à jour" });

        log("INFO", "admin_set_credits", { by: req.user.id, target: userData.id, action, amount: amt, ip: req.ip });
        res.json({ success: true, action, new_value: newVal, user: updated[0] });
    } catch (e) {
        log("ERROR", "set_credits_fail", { msg: e.message, ip: req.ip });
        res.status(500).json({ error: "Erreur serveur: " + e.message });
    }
});

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

app.get("/api/stats/dashboard", requireAuth, statsLimiter, (req, res) => {
    res.json({ ...statsCache, timestamp: new Date().toISOString() });
});

app.post("/verify-captcha", captchaLimiter, async (req, res) => {
    const { token, csrfNonce } = req.body;
    if (!consumeCsrfNonce(csrfNonce))       return res.status(403).json({ success: false, message: "CSRF invalide" });
    if (!token || typeof token !== "string") return res.status(400).json({ success: false, message: "Token manquant" });
    if (token.length > 2048)                return res.status(400).json({ success: false, message: "Token invalide" });
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

const notifyLimiter = mkLimiter(60 * 1000, 10, "Trop de notifications.");
async function sendWebhook(payload) {
    if (!WEBHOOK_URL || WEBHOOK_URL.includes("ICI")) return;
    try {
        await fetch(WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    } catch (e) { log("WARN", "webhook_fail", { msg: e.message }); }
}

app.post("/api/notify-register", notifyLimiter, async (req, res) => {
    const { email } = req.body;
    if (!email || typeof email !== "string" || !validateEmail(email)) return res.status(400).json({ error: "Email invalide" });
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
    log("INFO", "new_register", { email: sanitize(email, 254), ip });
    await sendWebhook({ embeds: [{ title: "Nouvelle inscription", color: 0x22c55e, fields: [
        { name: "Email", value: sanitize(email, 254), inline: true },
        { name: "IP", value: ip, inline: true },
        { name: "Date", value: new Date().toLocaleString("fr-FR"), inline: false }
    ]}]});
    res.json({ success: true });
});

app.post("/api/notify-login", requireAuth, notifyLimiter, async (req, res) => {
    const { email } = req.body;
    if (!email || typeof email !== "string" || !validateEmail(email)) return res.status(400).json({ error: "Email invalide" });
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
    log("INFO", "user_login", { uid: req.user?.id, email: sanitize(email, 254), ip });
    await sendWebhook({ embeds: [{ title: "Connexion utilisateur", color: 0x60a5fa, fields: [
        { name: "Email", value: sanitize(email, 254), inline: true },
        { name: "IP", value: ip, inline: true },
        { name: "UID", value: req.user?.id || "—", inline: false },
        { name: "Date", value: new Date().toLocaleString("fr-FR"), inline: false }
    ]}]});
    res.json({ success: true });
});

const VALID_SEARCH_TYPES  = new Set(["email","username","phone","ip","domain","name","hash","auto","url","machine_id"]);
const VALID_STEALER_TYPES = new Set(["email","username","ip","domain","url","machine_id","auto"]);
const SK_BASE = "https://see-know.eu/api/v1";

function skHeaders() {
    return { "X-API-Key": SEEKNOW_API_KEY, "Content-Type": "application/json" };
}

async function doSeeKnow(query, type, uid, ip) {
    if (!SEEKNOW_API_KEY || SEEKNOW_API_KEY.includes("ICI"))
        throw { status: 503, error: "Service de recherche non configuré." };
    const sanitizedQuery = query.trim().substring(0, 300);
    const isStealerEndpoint = type === "stealer";
    const endpoint = isStealerEndpoint ? `${SK_BASE}/stealer` : `${SK_BASE}/search`;
    const bodyType = isStealerEndpoint ? "auto" : type;
    const start = Date.now();
    const skRes = await fetch(endpoint, {
        method: "POST",
        headers: skHeaders(),
        body: JSON.stringify({ query: sanitizedQuery, type: bodyType })
    });
    const responseTime = Date.now() - start;
    if (!skRes.ok) {
        log("WARN", "seeknow_api_error", { status: skRes.status, ip, uid });
        const errBody = await skRes.json().catch(() => ({}));
        const SK_ERRORS = {
            401: { status: 502, error: "Clé API SeeKnow invalide. Contactez un administrateur." },
            402: { status: 402, error: "Crédits SeeKnow insuffisants. Réessayez demain ou upgradez votre plan." },
            403: { status: 403, error: "Accès refusé par SeeKnow — votre plan ne permet pas cette recherche." },
            404: { status: 404, error: "Aucun résultat trouvé." },
            429: { status: 429, error: "Limite de requêtes SeeKnow atteinte. Réessayez dans quelques secondes." },
        };
        const mapped = SK_ERRORS[skRes.status];
        if (mapped) throw mapped;
        throw { status: 502, error: errBody.message || `Erreur upstream SeeKnow (${skRes.status}).`, detail: skRes.status };
    }
    const raw = await skRes.json();
    log("INFO", "seeknow_search", { uid, ip, type, total: raw.total, ms: responseTime });

    const rawResults = raw.results || raw.data || [];
    let normalized;
    if (rawResults.length === 0) {
        normalized = [];
    } else {
        const first = rawResults[0];
        const isAlreadyGrouped = first && (first.database != null || Array.isArray(first.data));
        if (isAlreadyGrouped) {
            normalized = rawResults;
        } else {
            const groups = new Map();
            for (const entry of rawResults) {
                const src = entry.source || entry.Source || entry._source || "Unknown";
                if (!groups.has(src)) groups.set(src, []);
                const { source, Source, _source, _origin, ...fields } = entry;
                groups.get(src).push(fields);
            }
            normalized = [];
            for (const [src, entries] of groups) {
                normalized.push({ database: src, infoLeak: "", data: entries });
            }
        }
    }

    return {
        success: raw.success !== false,
        query: raw.query || query,
        type: raw.type || type,
        total: raw.total ?? rawResults.length,
        breach_count: raw.breach_count ?? (isStealerEndpoint ? null : normalized.length),
        stealer_count: raw.stealer_count ?? (isStealerEndpoint ? normalized.length : null),
        results: normalized,
        response_time_ms: responseTime
    };
}

async function doSeeKnowGet(skPath, params, uid, ip) {
    if (!SEEKNOW_API_KEY || SEEKNOW_API_KEY.includes("ICI"))
        throw { status: 503, error: "Service OSINT non configuré." };
    const qs = new URLSearchParams(params).toString();
    const start = Date.now();
    const skRes = await fetch(`${SK_BASE}${skPath}?${qs}`, {
        method: "GET", headers: { "X-API-Key": SEEKNOW_API_KEY }
    });
    const responseTime = Date.now() - start;
    if (!skRes.ok) {
        const errBody = await skRes.json().catch(() => ({}));
        log("WARN", "seeknow_osint_error", { skPath, status: skRes.status, ip, uid });
        const SK_ERRORS = {
            401: { status: 502, error: "Clé API SeeKnow invalide. Contactez un administrateur." },
            402: { status: 402, error: "Crédits SeeKnow insuffisants. Réessayez demain ou upgradez votre plan." },
            403: { status: 403, error: "Accès refusé par SeeKnow — votre plan ne permet pas cette recherche ou la ressource est introuvable." },
            404: { status: 404, error: "Aucun résultat trouvé pour cette requête." },
            429: { status: 429, error: "Limite de requêtes SeeKnow atteinte. Réessayez dans quelques secondes." },
        };
        const mapped = SK_ERRORS[skRes.status];
        if (mapped) throw mapped;
        throw { status: 502, error: errBody.message || `Erreur upstream SeeKnow (${skRes.status}).` };
    }
    const data = await skRes.json();
    log("INFO", "seeknow_osint", { uid, ip, skPath, ms: responseTime });
    return { ...data, response_time_ms: responseTime };
}

app.post("/api/search", requireAuth, searchLimiter, async (req, res) => {
    const { query, type = "auto" } = req.body;
    if (!query || typeof query !== "string" || query.trim().length < 2)
        return res.status(400).json({ error: "Paramètre 'query' invalide (2 caractères minimum)." });
    if (!VALID_SEARCH_TYPES.has(type))
        return res.status(400).json({ error: "Type de recherche invalide." });
    const sanction = await getSanction(req.user.id);
    if (sanction.banned)       return res.status(403).json({ error: "Votre compte est banni. Contactez le support." });
    if (sanction.blockSearch)  return res.status(403).json({ error: "Votre accès à la recherche a été bloqué par un administrateur." });
    try {
        const data = await doSeeKnow(query, type, req.user.id, req.ip);
        pushActivity(req.user.id, { type: "search", description: `Search: "${query.trim().substring(0,80)}" (${type}) → ${data.total} résultats`, ip: req.ip });
        res.json(data);
    } catch (e) {
        if (e.status) return res.status(e.status).json({ error: e.error, detail: e.detail });
        log("ERROR", "seeknow_fetch_fail", { msg: e.message, ip: req.ip });
        res.status(502).json({ error: "Impossible de joindre l'API SeeKnow." });
    }
});

app.post("/api/stealer", requireAuth, searchLimiter, async (req, res) => {
    const { query, type = "auto" } = req.body;
    if (!query || typeof query !== "string" || query.trim().length < 2)
        return res.status(400).json({ error: "Paramètre 'query' invalide (2 caractères minimum)." });
    if (!VALID_STEALER_TYPES.has(type))
        return res.status(400).json({ error: "Type invalide pour stealer." });
    const sanction = await getSanction(req.user.id);
    if (sanction.banned)       return res.status(403).json({ error: "Votre compte est banni. Contactez le support." });
    if (sanction.blockSearch)  return res.status(403).json({ error: "Votre accès à la recherche a été bloqué par un administrateur." });
    try {
        const data = await doSeeKnow(query, "stealer", req.user.id, req.ip);
        pushActivity(req.user.id, { type: "search", description: `Stealer: "${query.trim().substring(0,80)}" → ${data.total} logs`, ip: req.ip });
        res.json(data);
    } catch (e) {
        if (e.status) return res.status(e.status).json({ error: e.error, detail: e.detail });
        log("ERROR", "stealer_fetch_fail", { msg: e.message, ip: req.ip });
        res.status(502).json({ error: "Impossible de joindre l'API SeeKnow." });
    }
});

app.get("/api/sk-credits", requireAuth, async (req, res) => {
    try {
        const data = await doSeeKnowGet("/credits", {}, req.user.id, req.ip);
        res.json(data);
    } catch (e) {
        if (e.status) return res.status(e.status).json({ error: e.error });
        res.status(502).json({ error: "Impossible de récupérer les crédits SeeKnow." });
    }
});

const osintLimiter = mkLimiter(60 * 1000, 30, "Trop de requêtes OSINT.");

function osintRoute(routePath, paramKey, skPath) {
    app.get(`/api/osint/${routePath}`, requireAuth, osintLimiter, async (req, res) => {
        const val = req.query[paramKey];
        if (!val || typeof val !== "string" || val.trim().length < 1)
            return res.status(400).json({ error: `Paramètre '${paramKey}' manquant.` });
        const sanction = await getSanction(req.user.id);
        if (sanction.banned) return res.status(403).json({ error: "Compte banni." });
        try {
            const data = await doSeeKnowGet(skPath, { [paramKey]: val.trim().substring(0, 200) }, req.user.id, req.ip);
            res.json(data);
        } catch (e) {
            if (e.status) return res.status(e.status).json({ error: e.error });
            res.status(502).json({ error: "Erreur API SeeKnow." });
        }
    });
}

osintRoute("discord-user",    "query",    "/discord/user");
osintRoute("discord-roblox",  "query",    "/discord/to-roblox");
osintRoute("github",          "username", "/username/github");
osintRoute("twitter",         "username", "/username/twitter");
osintRoute("tiktok",          "username", "/username/tiktok");
osintRoute("reddit",          "username", "/username/reddit");
osintRoute("social",          "username", "/username/social");
osintRoute("username-history","username", "/username/history");
osintRoute("xbox",            "username", "/gaming/xbox");
osintRoute("roblox",          "username", "/gaming/roblox");
osintRoute("minecraft",       "username", "/gaming/minecraft");
osintRoute("ip",              "ip",       "/network/ip");
osintRoute("email-check",     "email",    "/network/email-check");
osintRoute("phone",           "phone",    "/network/phone");
osintRoute("domain-intel",    "domain",   "/domain/intel");
osintRoute("whois",           "domain",   "/domain/whois");

app.get("/api/auth/me", requireAuth, async (req, res) => {
    if (!supabaseAdmin) return res.status(503).json({ error: "Service indisponible" });
    try {
        const { data: user, error } = await supabaseAdmin
            .from("users").select("*").eq("auth_id", req.user.id).maybeSingle();
        if (error || !user) return res.status(404).json({ error: "Utilisateur introuvable" });
        res.json({
            auth_id:             user.auth_id,
            email:               user.email,
            username:            user.username || user.chat_pseudo || user.email?.split("@")[0],
            abonnement:          user.plan || "free",
            plan:                user.plan || "free",
            daily_searches_used: Math.max(0, (user.max_credits || 10) - (user.credits || 0)),
            daily_limit:         user.max_credits || 10,
            max_credits:         user.max_credits || 10,
            credits:             user.credits ?? 0,
            total_searches:      user.total_searches || 0,
            key:                 user.key || null,
            ip_whitelist:        user.ip_whitelist || [],
            is_admin:            ADMIN_UIDS.has(req.user.id)
        });
    } catch (e) { res.status(500).json({ error: "Erreur serveur" }); }
});

app.post("/api/register", requireAuth, async (req, res) => {
    if (!supabaseAdmin) return res.json({ success: true });
    const { username } = req.body;
    try {
        const existing = await supabaseAdmin.from("users").select("id").eq("auth_id", req.user.id).maybeSingle();
        if (!existing.data) {
            await supabaseAdmin.from("users").insert({
                auth_id:     req.user.id,
                email:       req.user.email,
                username:    username ? sanitize(username, 50) : req.user.email?.split("@")[0],
                plan:        "free",
                credits:     10,
                max_credits: 10
            });
        }
        res.json({ success: true });
    } catch (e) { res.json({ success: true }); }
});


app.post("/api/v1/search", requireAuth, searchLimiter, async (req, res) => {
    const { query, type = "auto" } = req.body;
    if (!query || typeof query !== "string" || query.trim().length < 2)
        return res.status(400).json({ error: "Paramètre 'query' invalide (2 caractères minimum)." });
    if (!VALID_SEARCH_TYPES.has(type))
        return res.status(400).json({ error: "Type de recherche invalide." });
    const sanction = await getSanction(req.user.id);
    if (sanction.banned)      return res.status(403).json({ error: "Votre compte est banni." });
    if (sanction.blockSearch) return res.status(403).json({ error: "Votre accès à la recherche est bloqué." });
    try {
        const data = await doSeeKnow(query, type, req.user.id, req.ip);
        pushActivity(req.user.id, { type: "search", description: `Search: "${query.trim().substring(0,80)}" → ${data.total} résultats`, ip: req.ip });
        res.json(data);
    } catch (e) {
        if (e.status) return res.status(e.status).json({ error: e.error, detail: e.detail });
        res.status(502).json({ error: "Impossible de joindre l'API SeeKnow." });
    }
});

app.post("/api/v1/stealer", requireAuth, searchLimiter, async (req, res) => {
    const { query, type = "auto" } = req.body;
    if (!query || typeof query !== "string" || query.trim().length < 2)
        return res.status(400).json({ error: "Paramètre 'query' invalide." });
    const sanction = await getSanction(req.user.id);
    if (sanction.banned)      return res.status(403).json({ error: "Votre compte est banni." });
    if (sanction.blockSearch) return res.status(403).json({ error: "Votre accès à la recherche est bloqué." });
    try {
        const data = await doSeeKnow(query, "stealer", req.user.id, req.ip);
        pushActivity(req.user.id, { type: "search", description: `Stealer: "${query.trim().substring(0,80)}" → ${data.total} logs`, ip: req.ip });
        res.json(data);
    } catch (e) {
        if (e.status) return res.status(e.status).json({ error: e.error });
        res.status(502).json({ error: "Impossible de joindre l'API SeeKnow." });
    }
});

app.get("/api/v1/auth/me", requireAuth, async (req, res) => {
    if (!supabaseAdmin) return res.status(503).json({ error: "Service indisponible" });
    try {
        const { data: user } = await supabaseAdmin.from("users").select("*").eq("auth_id", req.user.id).maybeSingle();
        if (!user) return res.status(404).json({ error: "Utilisateur introuvable" });
        res.json({
            auth_id: user.auth_id, email: user.email,
            username: user.username || user.chat_pseudo || user.email?.split("@")[0],
            abonnement: user.plan || "free", plan: user.plan || "free",
            daily_searches_used: Math.max(0, (user.max_credits||10) - (user.credits||0)),
            daily_limit: user.max_credits || 10, max_credits: user.max_credits || 10,
            credits: user.credits ?? 0, total_searches: user.total_searches || 0,
            key: user.key || null, ip_whitelist: user.ip_whitelist || [],
            is_admin: ADMIN_UIDS.has(req.user.id)
        });
    } catch (e) { res.status(500).json({ error: "Erreur serveur" }); }
});

app.get("/api/v1/account/notifications", requireAuth, async (req, res) => {
    const n = userNotifications.get(req.user.id) || [];
    res.json({ success: true, notifications: n, unread_count: n.filter(x => !x.read).length });
});
app.post("/api/v1/account/notifications/read-all", requireAuth, async (req, res) => {
    const n = userNotifications.get(req.user.id) || [];
    n.forEach(x => { x.read = true; });
    res.json({ success: true });
});
app.delete("/api/v1/account/notifications/:id", requireAuth, async (req, res) => {
    const n = (userNotifications.get(req.user.id) || []).filter(x => x.id !== req.params.id);
    userNotifications.set(req.user.id, n);
    res.json({ success: true });
});

app.get("/api/v1/auth/sessions", requireAuth, async (req, res) => {
    let sessions = activeSessions.get(req.user.id) || [];
    if (supabaseAdmin && sessions.length === 0) {
        try {
            const { data } = await supabaseAdmin.from("sessions")
                .select("*").eq("auth_id", req.user.id)
                .order("last_activity", { ascending: false }).limit(10);
            if (data && data.length > 0) {
                sessions = data.map(s => ({
                    sessionId:    s.id || s.session_id,
                    browser:      s.browser || s.user_agent || "Browser",
                    device:       s.device || "Unknown",
                    ip:           s.ip_address || s.ip || "—",
                    lastActivity: s.last_activity || s.created_at,
                    isCurrent:    s.is_current || false
                }));
            }
        } catch (_) {}
    }
    res.json({ success: true, sessions });
});

app.post("/api/v1/auth/track-session", requireAuth, async (req, res) => {
    const { browser, device, sessionId } = req.body;
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
    const sid = sessionId || `sess_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
    const sessionData = {
        sessionId: sid,
        browser:      sanitize(browser || "Browser", 100),
        device:       sanitize(device || "Desktop", 100),
        ip,
        lastActivity: new Date().toISOString(),
        isCurrent:    true
    };
    const sessions = activeSessions.get(req.user.id) || [];
    sessions.forEach(s => { s.isCurrent = false; });
    sessions.unshift(sessionData);
    if (sessions.length > 10) sessions.length = 10;
    activeSessions.set(req.user.id, sessions);

    if (supabaseAdmin) {
        try {
            await supabaseAdmin.from("sessions").upsert({
                session_id:    sid,
                auth_id:       req.user.id,
                browser:       sessionData.browser,
                device:        sessionData.device,
                ip_address:    ip,
                last_activity: sessionData.lastActivity,
                is_current:    true
            }, { onConflict: "session_id" });
        } catch (_) {}
    }
    pushActivity(req.user.id, {
        type: "login",
        description: `Connexion depuis ${ip} (${sessionData.browser})`,
        ip,
        timestamp: new Date().toISOString()
    });
    res.json({ success: true, session: sessionData });
});

app.delete("/api/v1/auth/sessions/:id", requireAuth, async (req, res) => {
    const sessions = (activeSessions.get(req.user.id) || []).filter(s => s.sessionId !== req.params.id);
    activeSessions.set(req.user.id, sessions);
    if (supabaseAdmin) {
        try { await supabaseAdmin.from("sessions").delete().eq("session_id", req.params.id).eq("auth_id", req.user.id); } catch (_) {}
    }
    res.json({ success: true });
});

app.post("/api/v1/auth/revoke-all-sessions", requireAuth, async (req, res) => {
    const current = (activeSessions.get(req.user.id) || []).filter(s => s.isCurrent);
    activeSessions.set(req.user.id, current);
    if (supabaseAdmin) {
        try { await supabaseAdmin.from("sessions").delete().eq("auth_id", req.user.id).eq("is_current", false); } catch (_) {}
    }
    res.json({ success: true });
});

app.get("/api/v1/account/activities", requireAuth, async (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    let acts = (userActivities.get(req.user.id) || []).slice(0, limit);
    if (supabaseAdmin && acts.length === 0) {
        try {
            const { data } = await supabaseAdmin.from("security_logs")
                .select("*").eq("user_id", req.user.id)
                .order("created_at", { ascending: false }).limit(limit);
            if (data) acts = data.map(l => ({
                id:          l.id,
                type:        l.action_type,
                description: l.action_description,
                timestamp:   l.created_at,
                ip:          l.ip_address
            }));
        } catch (_) {}
    }
    res.json({ success: true, activities: acts });
});

app.get("/api/v1/security/logs", requireAuth, async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    let logs = [];
    if (supabaseAdmin) {
        try {
            const { data } = await supabaseAdmin.from("security_logs")
                .select("*").eq("user_id", req.user.id)
                .order("created_at", { ascending: false }).limit(limit);
            logs = data || [];
        } catch (_) {}
    }
    if (logs.length === 0) {
        const memActs = userActivities.get(req.user.id) || [];
        logs = memActs.slice(0, limit).map(a => ({
            id:                 a.id,
            action_type:        a.type,
            action_description: a.description,
            created_at:         a.created_at || a.timestamp,
            ip_address:         a.ip
        }));
    }
    res.json({ success: true, logs, total: logs.length });
});

app.post("/api/v1/history", requireAuth, historyLimiter, async (req, res) => {
    const { query, search_type, total_results, response_time_ms } = req.body;
    if (!query || typeof query !== "string") return res.status(400).json({ error: "query requis" });
    if (supabaseAdmin) {
        try {
            await supabaseAdmin.from("search_logs").insert({
                auth_id:          req.user.id,
                query:            sanitize(query, 300),
                search_type:      sanitize(search_type || "auto", 50),
                total_results:    parseInt(total_results) || 0,
                response_time_ms: parseInt(response_time_ms) || 0,
                ip_address:       req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip
            });
        } catch (e) {
            log("WARN", "history_insert_fail", { msg: e.message });
        }
    }
    res.json({ success: true });
});

app.get("/api/v1/history", requireAuth, historyLimiter, async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const page  = Math.max(parseInt(req.query.page) || 0, 0);
    let rows = [];
    if (supabaseAdmin) {
        try {
            const { data } = await supabaseAdmin.from("search_logs")
                .select("*")
                .eq("auth_id", req.user.id)
                .order("created_at", { ascending: false })
                .range(page * limit, (page + 1) * limit - 1);
            rows = data || [];
        } catch (e) {
            log("WARN", "history_fetch_fail", { msg: e.message });
        }
    }
    res.json({ success: true, history: rows, total: rows.length });
});

app.post("/api/v1/auth/update-password", requireAuth, async (req, res) => {
    if (!supabaseAdmin) return res.status(503).json({ error: "Service indisponible" });
    const { newPassword } = req.body;
    if (!newPassword || typeof newPassword !== "string" || newPassword.length < 8)
        return res.status(400).json({ error: "Mot de passe invalide (8 caractères minimum)" });
    if (!/(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9])/.test(newPassword))
        return res.status(400).json({ error: "Le mot de passe doit contenir 1 majuscule, 1 chiffre, 1 symbole" });
    try {
        const { error } = await supabaseAdmin.auth.admin.updateUserById(req.user.id, { password: newPassword });
        if (error) return res.status(400).json({ error: error.message });
        log("INFO", "password_changed", { uid: req.user.id, ip: req.ip });
        pushActivity(req.user.id, { type: "security", description: "Mot de passe modifié", ip: req.ip });
        res.json({ success: true, message: "Mot de passe mis à jour" });
    } catch (e) { res.status(500).json({ error: "Erreur serveur" }); }
});

app.post("/api/v1/account/update-preferences", requireAuth, async (req, res) => {
    const { displayName } = req.body;
    if (!displayName || typeof displayName !== "string" || !displayName.trim())
        return res.status(400).json({ error: "Nom invalide" });
    if (!supabaseAdmin) return res.json({ success: true });
    try {
        await supabaseAdmin.from("users").update({ username: sanitize(displayName.trim(), 50) }).eq("auth_id", req.user.id);
        userPreferences.set(req.user.id, { displayName: displayName.trim() });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Erreur serveur" }); }
});

app.post("/api/v1/account/reset-api-key", requireAuth, async (req, res) => {
    const cooldown = keyResetCooldowns.get(req.user.id);
    if (cooldown && Date.now() - cooldown < 48 * 3600 * 1000) {
        const remain = Math.ceil((48 * 3600 * 1000 - (Date.now() - cooldown)) / 3600000);
        return res.status(429).json({ error: `Cooldown actif — disponible dans ${remain}h` });
    }
    const newKey = "sk-" + crypto.randomBytes(24).toString("hex").slice(0, 32);
    keyResetCooldowns.set(req.user.id, Date.now());
    if (supabaseAdmin) {
        try { await supabaseAdmin.from("users").update({ key: newKey }).eq("auth_id", req.user.id); } catch (_) {}
    }
    log("INFO", "api_key_reset", { uid: req.user.id, ip: req.ip });
    res.json({ success: true, newKey });
});

app.get("/api/v1/account/key-reset-status", requireAuth, async (req, res) => {
    const cooldown = keyResetCooldowns.get(req.user.id);
    if (!cooldown || Date.now() - cooldown >= 48 * 3600 * 1000)
        return res.json({ canReset: true });
    const remain = Math.ceil((48 * 3600 * 1000 - (Date.now() - cooldown)) / 3600000);
    res.json({ canReset: false, timeRemaining: remain + "h" });
});

app.get("/api/v1/sk-credits", requireAuth, async (req, res) => {
    try {
        const data = await doSeeKnowGet("/credits", {}, req.user.id, req.ip);
        res.json(data);
    } catch (e) {
        if (e.status) return res.status(e.status).json({ error: e.error });
        res.status(502).json({ error: "Impossible de récupérer les crédits SeeKnow." });
    }
});

function osintV1Route(routePath, paramKey, skPath) {
    app.get(`/api/v1/osint/${routePath}`, requireAuth, osintLimiter, async (req, res) => {
        const val = req.query[paramKey];
        if (!val) return res.status(400).json({ error: `Paramètre '${paramKey}' manquant.` });
        const sanction = await getSanction(req.user.id);
        if (sanction.banned) return res.status(403).json({ error: "Compte banni." });
        try {
            const data = await doSeeKnowGet(skPath, { [paramKey]: val.trim().substring(0, 200) }, req.user.id, req.ip);
            res.json(data);
        } catch (e) {
            if (e.status) return res.status(e.status).json({ error: e.error });
            res.status(502).json({ error: "Erreur API SeeKnow." });
        }
    });
}

osintV1Route("discord-user",    "query",    "/discord/user");
osintV1Route("discord-roblox",  "query",    "/discord/to-roblox");
osintV1Route("github",          "username", "/username/github");
osintV1Route("twitter",         "username", "/username/twitter");
osintV1Route("tiktok",          "username", "/username/tiktok");
osintV1Route("reddit",          "username", "/username/reddit");
osintV1Route("social",          "username", "/username/social");
osintV1Route("ip",              "ip",       "/network/ip");
osintV1Route("email-check",     "email",    "/network/email-check");
osintV1Route("phone",           "phone",    "/network/phone");
osintV1Route("domain-intel",    "domain",   "/domain/intel");
osintV1Route("whois",           "domain",   "/domain/whois");
osintV1Route("roblox",          "username", "/gaming/roblox");
osintV1Route("xbox",            "username", "/gaming/xbox");
osintV1Route("minecraft",       "username", "/gaming/minecraft");

app.use((req, res) => res.status(404).json({ error: "Route non trouvée" }));
app.use((err, req, res, _next) => {
    log("ERROR", "unhandled", { msg: err.message });
    res.status(500).json({ error: "Erreur interne" });
});

server.listen(PORT, () => log("INFO", "server_start", { port: PORT }));
