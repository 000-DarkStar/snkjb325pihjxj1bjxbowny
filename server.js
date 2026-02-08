const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const fetch = require("node-fetch");
const cors = require("cors");

const app = express();
const server = http.createServer(app);

const io = socketIo(server, {
  cors: { 
    origin: "*", // Accepte toutes les origines
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Configuration
const TURNSTILE_SECRET = "0x4AAAAAACXtOAo2YMkszq-RYglD_O_URx8";
const PORT = process.env.PORT || 3000;

// Middlewares - CORS étendu pour permettre les tests locaux
app.use(cors({
  origin: "*", // Accepte toutes les origines (local + production)
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

// Health check
app.get("/health", (req, res) => {
  console.log("✅ Health check");
  res.json({ 
    status: "ok",
    timestamp: new Date().toISOString(),
    turnstile: "configured"
  });
});

// Vérification Turnstile
app.post("/verify-captcha", async (req, res) => {
  console.log("\n🔐 === VÉRIFICATION CAPTCHA ===");
  console.log("📦 Body:", req.body);
  
  const { token } = req.body;
  
  if (!token) {
    console.log("❌ Token manquant");
    return res.json({ 
      success: false, 
      message: "Token captcha manquant" 
    });
  }

  console.log("🎫 Token reçu:", token.substring(0, 50) + "...");

  try {
    console.log("📡 Envoi à Cloudflare...");
    
    const formData = `secret=${encodeURIComponent(TURNSTILE_SECRET)}&response=${encodeURIComponent(token)}`;
    
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { 
        "Content-Type": "application/x-www-form-urlencoded" 
      },
      body: formData
    });

    const data = await response.json();
    console.log("📊 Réponse Cloudflare:", JSON.stringify(data, null, 2));
    
    if (data.success) {
      console.log("✅ ✅ ✅ CAPTCHA VALIDÉ ✅ ✅ ✅");
      return res.json({ 
        success: true,
        message: "Captcha vérifié avec succès"
      });
    } else {
      console.log("❌ CAPTCHA REJETÉ");
      console.log("🚫 Erreurs:", data["error-codes"]);
      return res.json({ 
        success: false, 
        message: "Captcha invalide ou expiré",
        errors: data["error-codes"]
      });
    }
  } catch (err) {
    console.error("💥 ERREUR:", err);
    return res.json({ 
      success: false, 
      message: "Erreur lors de la vérification du captcha",
      error: err.message
    });
  }
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
      <title>Backend DeadEyes - Test</title>
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
      <p class="info">🔑 Turnstile configuré: Oui</p>
      
      <h2>📡 Endpoints disponibles:</h2>
      <ul>
        <li><strong>GET /health</strong> - Health check</li>
        <li><strong>POST /verify-captcha</strong> - Vérification Turnstile</li>
        <li><strong>GET /api/status</strong> - Statut serveur</li>
        <li><strong>GET /test</strong> - Cette page</li>
      </ul>

      <h2>🧪 Test rapide:</h2>
      <p>Pour tester la vérification captcha, utilisez:</p>
      <pre style="background: #000; padding: 1rem; border-radius: 4px; overflow-x: auto;">
curl -X POST https://snkjb325pihjxj1bjxbowny.onrender.com/verify-captcha \\
  -H "Content-Type: application/json" \\
  -d '{"token":"votre_token_ici"}'
      </pre>
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
  console.log(`🔑 Turnstile Secret: Configurée`);
  console.log(`🌍 CORS: Accepte toutes les origines`);
  console.log("=".repeat(70) + "\n");
  console.log("✅ Prêt à recevoir des requêtes!\n");
});
