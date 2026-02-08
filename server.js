const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const fetch = require("node-fetch");
const cors = require("cors");

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { 
    origin: "https://searchlabs.pages.dev",
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Configuration
const TURNSTILE_SECRET = "0x4AAAAAACXtOAo2YMkszq-RYglD_O_URx8";
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors({
  origin: "https://searchlabs.pages.dev",
  methods: ["GET", "POST"],
  credentials: true
}));
app.use(express.json());

// Compteur utilisateurs
let users = 0;

io.on("connection", (socket) => {
  users++;
  io.emit("users", users);
  
  socket.on("disconnect", () => {
    users--;
    io.emit("users", users);
  });
});

// Vérification Turnstile
app.post("/verify-captcha", async (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.json({ 
      success: false, 
      message: "Token captcha manquant" 
    });
  }

  try {
    console.log("🔐 Vérification captcha...");
    
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { 
        "Content-Type": "application/x-www-form-urlencoded" 
      },
      body: `secret=${TURNSTILE_SECRET}&response=${token}`
    });

    const data = await response.json();
    
    console.log("📡 Réponse Cloudflare:", data);
    
    if (data.success) {
      console.log("✅ Captcha validé");
      return res.json({ 
        success: true,
        message: "Captcha vérifié avec succès" 
      });
    } else {
      console.log("❌ Captcha invalide:", data["error-codes"]);
      return res.json({ 
        success: false, 
        message: "Captcha invalide ou expiré",
        errors: data["error-codes"]
      });
    }
  } catch (err) {
    console.error("❌ Erreur serveur:", err);
    return res.json({ 
      success: false, 
      message: "Erreur lors de la vérification du captcha" 
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

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Démarrage
server.listen(PORT, () => {
  console.log(`✅ Serveur démarré sur le port ${PORT}`);
  console.log(`🌐 CORS autorisé pour: https://searchlabs.pages.dev`);
});
