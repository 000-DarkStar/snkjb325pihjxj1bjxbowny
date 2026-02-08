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

// Compteur utilisateurs
let users = 0;

io.on("connection", (socket) => {
  users++;
  console.log(`👤 Utilisateur connecté. Total: ${users}`);
  io.emit("users", users);
  
  socket.on("disconnect", () => {
    users--;
    console.log(`👋 Utilisateur déconnecté. Total: ${users}`);
    io.emit("users", users);
  });
});

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
    timestamp: new Date().toISOString()
  });
});

// Route de test
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
          max-width: 800px;
          margin: 0 auto;
        }
        h1 { color: #00ff00; border-bottom: 2px solid #00ff00; padding-bottom: 1rem; }
        .info { color: #00aaff; margin: 0.5rem 0; }
        .success { color: #00ff00; font-weight: bold; }
        ul { margin: 1rem 0; }
        li { margin: 0.5rem 0; }
      </style>
    </head>
    <body>
      <h1 class="success">✅ Backend DeadEyes Opérationnel!</h1>
      <p class="info">🕐 ${new Date().toISOString()}</p>
      <p class="info">📍 Port: ${PORT}</p>
      <p class="info">👥 Utilisateurs connectés: ${users}</p>
      
      <h2>📡 Endpoints disponibles:</h2>
      <ul>
        <li><strong>GET /</strong> - Redirection vers /test</li>
        <li><strong>GET /health</strong> - Health check</li>
        <li><strong>GET /api/status</strong> - Statut serveur</li>
        <li><strong>WebSocket</strong> - Compteur utilisateurs en temps réel</li>
      </ul>
      
      <h2>ℹ️ Note:</h2>
      <p>La vérification captcha est maintenant gérée directement par Supabase.</p>
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

// Démarrage
server.listen(PORT, () => {
  console.log("\n" + "=".repeat(70));
  console.log("🚀 SERVEUR DEADEYES DÉMARRÉ");
  console.log("=".repeat(70));
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌐 URL: https://snkjb325pihjxj1bjxbowny.onrender.com`);
  console.log(`🌍 CORS: Accepte toutes les origines`);
  console.log(`📊 WebSocket: Compteur utilisateurs activé`);
  console.log("=".repeat(70) + "\n");
  console.log("✅ Prêt à recevoir des requêtes!\n");
});
