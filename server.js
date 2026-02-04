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
const TURNSTILE_SECRET = "0x4AAAAAACXtON1ce0GeOud1iJJ6Uve9U7U";
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
app.post("/verify", async (req, res) => {
  const token = req.body.token;
  
  if (!token) {
    return res.json({ success: false, message: "Token manquant" });
  }

  try {
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${TURNSTILE_SECRET}&response=${token}`
    });

    const data = await response.json();
    
    if (data.success) {
      return res.json({ success: true });
    } else {
      return res.json({ success: false, message: "Captcha invalide" });
    }
  } catch (err) {
    return res.json({ success: false, message: "Erreur serveur" });
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

// Démarrage
server.listen(PORT, () => {
  console.log(`✅ Serveur sur le port ${PORT}`);
});
