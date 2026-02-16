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

// Route de test avec info complète
app.get("/test", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Backend DeadEyes</title>
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
      <h1 class="success">✅ Backend DeadEyes Opérationnel!</h1>
      <p class="info">🕐 ${new Date().toISOString()}</p>
      <p class="info">📍 Port: ${PORT}</p>
      <p class="info">👥 Utilisateurs en ligne: ${users}</p>
      <p class="info">💬 Messages en mémoire: ${chatMessages.length}</p>
      
      <div class="section">
        <h2>📡 Endpoints Standards:</h2>
        <ul>
          <li class="endpoint">
            <span class="method">GET</span> <code>/</code> - Redirection vers /test
          </li>
          <li class="endpoint">
            <span class="method">GET</span> <code>/health</code> - Health check
          </li>
          <li class="endpoint">
            <span class="method">GET</span> <code>/api/status</code> - Statut serveur + users en ligne
          </li>
        </ul>
      </div>

      <div class="section">
        <h2>💬 Endpoints Chat:</h2>
        <ul>
          <li class="endpoint">
            <span class="method">GET</span> <code>/api/chat/messages?limit=50</code><br>
            → Récupérer l'historique des messages
          </li>
          <li class="endpoint">
            <span class="method">GET</span> <code>/api/chat/stats</code><br>
            → Statistiques du chat (messages, users connectés)
          </li>
        </ul>
      </div>

      <div class="section">
        <h2>📊 Endpoints Stats:</h2>
        <ul>
          <li class="endpoint">
            <span class="method">GET</span> <code>/api/stats/dashboard</code><br>
            → Stats globales (lignes indexées, recherches, users)
          </li>
        </ul>
      </div>

      <div class="section">
        <h2>🔌 Socket.IO Events:</h2>
        <h3>📤 Émis par le client:</h3>
        <ul>
          <li class="endpoint">
            <code>chat:join</code> - Se connecter au chat<br>
            Payload: <code>{ pseudo: "username" }</code>
          </li>
          <li class="endpoint">
            <code>chat:send</code> - Envoyer un message<br>
            Payload: <code>{ pseudo: "username", content: "message", id: "optional" }</code>
          </li>
          <li class="endpoint">
            <code>chat:typing</code> - Indicateur de frappe<br>
            Payload: <code>{ pseudo: "username", isTyping: true }</code>
          </li>
        </ul>

        <h3>📥 Reçus par le client:</h3>
        <ul>
          <li class="endpoint">
            <code>users</code> - Nombre d'utilisateurs en ligne<br>
            Payload: <code>number</code>
          </li>
          <li class="endpoint">
            <code>chat:history</code> - Historique des messages (à la connexion)<br>
            Payload: <code>Array&lt;Message&gt;</code>
          </li>
          <li class="endpoint">
            <code>chat:message</code> - Nouveau message<br>
            Payload: <code>{ id, pseudo, content, created_at, isSystem? }</code>
          </li>
          <li class="endpoint">
            <code>chat:userTyping</code> - Un utilisateur est en train de taper<br>
            Payload: <code>{ pseudo, isTyping }</code>
          </li>
          <li class="endpoint">
            <code>chat:error</code> - Erreur<br>
            Payload: <code>{ message: "error message" }</code>
          </li>
        </ul>
      </div>

      <div class="section">
        <h2 class="warning">⚙️ Fonctionnalités:</h2>
        <ul>
          <li>✅ WebSocket en temps réel (Socket.io)</li>
          <li>✅ Chat en direct avec historique (100 derniers messages)</li>
          <li>✅ Messages système (join/leave)</li>
          <li>✅ Indicateur de frappe (typing)</li>
          <li>✅ Validation des messages (max 1000 caractères)</li>
          <li>✅ CORS configuré pour accepter toutes les origines</li>
          <li>✅ Compteur d'utilisateurs en temps réel</li>
        </ul>
      </div>

      <div class="section">
        <h2>ℹ️ Notes:</h2>
        <ul>
          <li>📝 Les messages sont stockés en mémoire (100 max)</li>
          <li>🔄 Le serveur redémarre = messages perdus</li>
          <li>💾 Pour persistence: connecter à Supabase ou MongoDB</li>
          <li>🔐 Authentification gérée par Supabase côté frontend</li>
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
  console.log("🚀 SERVEUR DEADEYES DÉMARRÉ");
  console.log("=".repeat(70));
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌐 URL: https://snkjb325pihjxj1bjxbowny.onrender.com`);
  console.log(`🌍 CORS: Accepte toutes les origines`);
  console.log(`📊 WebSocket: Compteur utilisateurs activé`);
  console.log(`💬 Chat: Système Socket.io activé`);
  console.log(`📝 Historique: ${MAX_MESSAGES} messages max en mémoire`);
  console.log("=".repeat(70) + "\n");
  console.log("✅ Prêt à recevoir des requêtes!\n");
});
