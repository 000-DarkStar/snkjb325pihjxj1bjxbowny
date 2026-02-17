const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const cors = require("cors");
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { 
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Configuration
const PORT = process.env.PORT || 3000;

// Mettre votre secret Turnstile en variable d'env sur Render
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";

// Middlewares
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logging
app.use((req, res, next) => {
  console.log(`📨 ${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ==================== ÉTAT DU SERVEUR ====================
let users = 0;
let chatMessages = []; // Stockage en mémoire des 100 derniers messages
const MAX_MESSAGES = 100;
const connectedUsers = new Map(); // Map<socketId, {pseudo, socketId}>

// ==================== SOCKET.IO - USERS & CHAT ====================
io.on("connection", (socket) => {
  users++;
  console.log(`👤 Utilisateur connecté. Total: ${users} | Socket ID: ${socket.id}`);
  
  // Envoyer le nombre d'utilisateurs à tous
  io.emit("users", users);
  
  // Envoyer l'historique des messages au nouveau connecté
  socket.emit("chat:history", chatMessages);
  
  // ===== ÉVÉNEMENT: USER SE CONNECTE AU CHAT AVEC SON PSEUDO =====
  socket.on("chat:join", (data) => {
    if (data && data.pseudo) {
      connectedUsers.set(socket.id, {
        pseudo: data.pseudo,
        socketId: socket.id
      });
      console.log(`💬 ${data.pseudo} a rejoint le chat`);
      
      // Message système: utilisateur a rejoint
      const systemMessage = {
        id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        pseudo: "SYSTEM",
        content: `${data.pseudo} a rejoint le chat`,
        created_at: new Date().toISOString(),
        isSystem: true
      };
      
      chatMessages.push(systemMessage);
      if (chatMessages.length > MAX_MESSAGES) {
        chatMessages.shift();
      }
      
      io.emit("chat:message", systemMessage);
    }
  });
  
  // ===== ÉVÉNEMENT: RECEVOIR UN NOUVEAU MESSAGE =====
  socket.on("chat:send", (data) => {
    console.log(`💬 Message reçu de ${data.pseudo}: ${data.content.substring(0, 50)}...`);
    
    // Valider le message
    if (!data.pseudo || !data.content) {
      socket.emit("chat:error", { message: "Pseudo et contenu requis" });
      return;
    }
    
    if (data.content.trim().length === 0) {
      socket.emit("chat:error", { message: "Le message ne peut pas être vide" });
      return;
    }
    
    if (data.content.length > 1000) {
      socket.emit("chat:error", { message: "Message trop long (max 1000 caractères)" });
      return;
    }
    
    // Créer l'objet message
    const message = {
      id: data.id || `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      pseudo: data.pseudo,
      content: data.content,
      created_at: new Date().toISOString()
    };
    
    // Ajouter aux messages en mémoire
    chatMessages.push(message);
    
    // Garder seulement les 100 derniers messages
    if (chatMessages.length > MAX_MESSAGES) {
      chatMessages.shift();
    }
    
    // Diffuser à tous les clients connectés
    io.emit("chat:message", message);
    
    console.log(`✅ Message diffusé à ${users} utilisateur(s)`);
  });
  
  // ===== ÉVÉNEMENT: UTILISATEUR TAPE (typing indicator) =====
  socket.on("chat:typing", (data) => {
    socket.broadcast.emit("chat:userTyping", {
      pseudo: data.pseudo,
      isTyping: data.isTyping
    });
  });
  
  // ===== ÉVÉNEMENT: DÉCONNEXION =====
  socket.on("disconnect", () => {
    users--;
    
    // Récupérer le pseudo de l'utilisateur déconnecté
    const user = connectedUsers.get(socket.id);
    if (user) {
      console.log(`👋 ${user.pseudo} déconnecté. Total: ${users}`);
      
      // Message système: utilisateur a quitté
      const systemMessage = {
        id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        pseudo: "SYSTEM",
        content: `${user.pseudo} a quitté le chat`,
        created_at: new Date().toISOString(),
        isSystem: true
      };
      
      chatMessages.push(systemMessage);
      if (chatMessages.length > MAX_MESSAGES) {
        chatMessages.shift();
      }
      
      io.emit("chat:message", systemMessage);
      
      // Supprimer de la map
      connectedUsers.delete(socket.id);
    } else {
      console.log(`👋 Utilisateur déconnecté. Total: ${users}`);
    }
    
    io.emit("users", users);
  });
});

// ==================== ROUTES API ====================

// Route racine (pour Render health checks)
app.get("/", (req, res) => {
  res.redirect("/test");
});

// Favicon (évite les erreurs 404)
app.get("/favicon.ico", (req, res) => {
  res.status(204).end();
});

// Health check
app.get("/health", (req, res) => {
  console.log("✅ Health check");
  res.json({ 
    status: "ok",
    timestamp: new Date().toISOString()
  });
});

// Route de status
app.get("/api/status", (req, res) => {
  res.json({
    status: "online",
    onlineUsers: users,
    totalMessages: chatMessages.length,
    timestamp: new Date().toISOString()
  });
});

// API: Récupérer l'historique du chat
app.get("/api/chat/messages", (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const messages = chatMessages.slice(-limit);
  
  res.json({
    messages: messages,
    total: messages.length,
    timestamp: new Date().toISOString()
  });
});

// API: Statistiques du chat
app.get("/api/chat/stats", (req, res) => {
  res.json({
    totalMessages: chatMessages.length,
    onlineUsers: users,
    connectedUsers: Array.from(connectedUsers.values()).map(u => u.pseudo),
    timestamp: new Date().toISOString()
  });
});

// API: Stats dashboard (lignes indexées, recherches, etc.)
app.get("/api/stats/dashboard", (req, res) => {
  res.json({
    indexedLines: "1.9B",
    totalSearches: "4.2M",
    registeredUsers: "106.6K",
    timestamp: new Date().toISOString()
  });
});

// ══════════════════════════════════════════════════════════════════
//  VÉRIFICATION CAPTCHA TURNSTILE
//  Appelé par register.html avant la création de compte Supabase
//  POST /verify-captcha
//  Body  : { token: string }
//  Retour: { success: bool, message?: string }
// ══════════════════════════════════════════════════════════════════
app.post("/verify-captcha", async (req, res) => {
  const { token } = req.body;

  if (!token || typeof token !== "string" || token.length > 2048) {
    return res.status(400).json({ success: false, message: "Token manquant ou invalide" });
  }

  // Mode dev: si le secret n'est pas configuré on laisse passer
  if (!TURNSTILE_SECRET) {
    console.warn("⚠️ [CAPTCHA] TURNSTILE_SECRET absent — vérification ignorée (mode dev)");
    return res.json({ success: true });
  }

  try {
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();

    const formBody = new URLSearchParams({
      secret: TURNSTILE_SECRET,
      response: token,
      remoteip: ip
    });

    const cfRes = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: formBody
    });

    const data = await cfRes.json();
    console.log(`🔒 [CAPTCHA] success=${data.success} | ip=${ip}`);

    if (!data.success) {
      return res.status(400).json({ success: false, message: "Captcha invalide, veuillez réessayer" });
    }

    res.json({ success: true });

  } catch (err) {
    console.error("❌ [CAPTCHA] Erreur:", err.message);
    res.status(500).json({ success: false, message: "Erreur serveur lors de la vérification" });
  }
});

// Route de test avec info complète
app.get("/test", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Backend Rapace</title>
      <style>
        body { 
          font-family: monospace; 
          padding: 2rem; 
          background: #0a0a0f; 
          color: #00ff00; 
          max-width: 900px;
          margin: 0 auto;
        }
        h1 { color: #00ff00; border-bottom: 2px solid #00ff00; padding-bottom: 1rem; }
        .info { color: #00aaff; margin: 0.5rem 0; }
        .success { color: #00ff00; font-weight: bold; }
        .warning { color: #fbbf24; font-weight: bold; }
        ul { margin: 1rem 0; }
        li { margin: 0.5rem 0; }
        .endpoint {
          background: #1a1a1a;
          padding: 0.75rem;
          border-left: 3px solid #00ff00;
          margin: 0.5rem 0;
          border-radius: 4px;
        }
        .method {
          color: #fbbf24;
          font-weight: bold;
          margin-right: 0.5rem;
        }
        code {
          background: #0a0a0a;
          padding: 0.2rem 0.4rem;
          border-radius: 3px;
          color: #10b981;
        }
        .section {
          margin: 2rem 0;
          padding: 1rem;
          background: #1a1a1a;
          border-radius: 8px;
          border: 1px solid #333;
        }
      </style>
    </head>
    <body>
      <h1 class="success">✅ Backend Rapace Opérationnel!</h1>
      <p class="info">🕐 ${new Date().toISOString()}</p>
      <p class="info">📍 Port: ${PORT}</p>
      <p class="info">👥 Utilisateurs en ligne: ${users}</p>
      <p class="info">💬 Messages en mémoire: ${chatMessages.length}/${MAX_MESSAGES}</p>
      <p class="info">🔒 Captcha: ${TURNSTILE_SECRET ? "CONFIGURÉ ✅" : "NON CONFIGURÉ (dev mode) ⚠️"}</p>
      
      <div class="section">
        <h2>📡 Endpoints Standards:</h2>
        <ul>
          <li class="endpoint"><span class="method">GET</span> <code>/</code> — Redirection vers /test</li>
          <li class="endpoint"><span class="method">GET</span> <code>/health</code> — Health check Render</li>
          <li class="endpoint"><span class="method">GET</span> <code>/api/status</code> — Statut + users en ligne</li>
        </ul>
      </div>

      <div class="section">
        <h2>🔒 Endpoint Captcha:</h2>
        <ul>
          <li class="endpoint">
            <span class="method">POST</span> <code>/verify-captcha</code><br>
            Body: <code>{ token: string }</code><br>
            Réponse: <code>{ success: bool, message?: string }</code><br>
            Variable env requise: <code>TURNSTILE_SECRET</code>
          </li>
        </ul>
      </div>

      <div class="section">
        <h2>💬 Endpoints Chat:</h2>
        <ul>
          <li class="endpoint"><span class="method">GET</span> <code>/api/chat/messages?limit=50</code><br>→ Récupérer l'historique des messages</li>
          <li class="endpoint"><span class="method">GET</span> <code>/api/chat/stats</code><br>→ Statistiques du chat</li>
        </ul>
      </div>

      <div class="section">
        <h2>📊 Endpoints Stats:</h2>
        <ul>
          <li class="endpoint"><span class="method">GET</span> <code>/api/stats/dashboard</code><br>→ Stats globales</li>
        </ul>
      </div>

      <div class="section">
        <h2>🔌 Socket.IO Events:</h2>
        <h3>📤 Émis par le client:</h3>
        <ul>
          <li class="endpoint"><code>chat:join</code> — <code>{ pseudo: "username" }</code></li>
          <li class="endpoint"><code>chat:send</code> — <code>{ pseudo: "username", content: "message" }</code></li>
          <li class="endpoint"><code>chat:typing</code> — <code>{ pseudo: "username", isTyping: true }</code></li>
        </ul>
        <h3>📥 Reçus par le client:</h3>
        <ul>
          <li class="endpoint"><code>users</code> — nombre d'utilisateurs (number)</li>
          <li class="endpoint"><code>chat:history</code> — historique à la connexion (Array)</li>
          <li class="endpoint"><code>chat:message</code> — <code>{ id, pseudo, content, created_at, isSystem? }</code></li>
          <li class="endpoint"><code>chat:userTyping</code> — <code>{ pseudo, isTyping }</code></li>
          <li class="endpoint"><code>chat:error</code> — <code>{ message }</code></li>
        </ul>
      </div>

      <div class="section">
        <h2 class="warning">⚙️ Config Render — Variables d'environnement:</h2>
        <ul>
          <li class="endpoint"><code>TURNSTILE_SECRET</code> — Secret Cloudflare Turnstile (obligatoire en prod)</li>
          <li class="endpoint"><code>NODE_ENV</code> — production</li>
          <li class="endpoint"><code>PORT</code> — défini automatiquement par Render</li>
        </ul>
      </div>

      <h2 class="success">✅ Serveur prêt à l'emploi!</h2>
    </body>
    </html>
  `);
});

// 404 handler
app.use((req, res) => {
  console.log(`❌ Route non trouvée: ${req.method} ${req.path}`);
  res.status(404).json({ 
    error: "Route non trouvée",
    path: req.path,
    method: req.method
  });
});

// ==================== DÉMARRAGE ====================
server.listen(PORT, () => {
  console.log("\n" + "=".repeat(70));
  console.log("🚀 SERVEUR RAPACE DÉMARRÉ");
  console.log("=".repeat(70));
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌐 URL: https://snkjb325pihjxj1bjxbowny.onrender.com`);
  console.log(`🌍 CORS: Accepte toutes les origines`);
  console.log(`📊 WebSocket: Compteur utilisateurs activé`);
  console.log(`💬 Chat: Système Socket.io activé`);
  console.log(`📝 Historique: ${MAX_MESSAGES} messages max en mémoire`);
  console.log(`🔒 Captcha: ${TURNSTILE_SECRET ? "CONFIGURÉ" : "NON CONFIGURÉ (set TURNSTILE_SECRET)"}`);
  console.log("=".repeat(70) + "\n");
  console.log("✅ Prêt à recevoir des requêtes!\n");
});
