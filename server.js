const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const fetch = require("node-fetch");
const cookieParser = require("cookie-parser");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // autorise Cloudflare Pages ou autre frontend
    methods: ["GET", "POST"]
  }
});

const SECRET_KEY = "TA_SECRET_KEY_ICI"; // remplace par ta clé secrète Cloudflare
const PORT = process.env.PORT || 3000;

let onlineUsers = 0;

// Middleware pour parser POST JSON et cookies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static("public")); // pour servir gate.html ou autres fichiers statiques

// --- Socket.io compteur d'utilisateurs ---
io.on("connection", (socket) => {
  onlineUsers++;
  io.emit("updateUsers", onlineUsers);

  socket.on("disconnect", () => {
    onlineUsers--;
    if (onlineUsers < 0) onlineUsers = 0;
    io.emit("updateUsers", onlineUsers);
  });
});

// --- Routes ---
app.get("/", (req, res) => {
  // Vérifie si captcha déjà validé via cookie
  if (req.cookies.captchaValidated) {
    res.sendFile(__dirname + "/public/home.html"); // ton vrai site
  } else {
    res.sendFile(__dirname + "/public/gate.html"); // page captcha
  }
});

// Route pour vérifier Turnstile
app.post("/verify-turnstile", async (req, res) => {
  const token = req.body["cf-turnstile-response"];
  if (!token) return res.status(400).json({ success: false, message: "Captcha manquant" });

  try {
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${SECRET_KEY}&response=${token}`
    });

    const data = await response.json();

    if (data.success) {
      // Captcha OK → on met un cookie pour éviter de refaire le captcha
      res.cookie("captchaValidated", "true", { maxAge: 24 * 60 * 60 * 1000 }); // 1 jour
      return res.json({ success: true });
    } else {
      return res.status(400).json({ success: false, message: "Échec du captcha" });
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// Page de test /home
app.get("/home", (req, res) => {
  res.sendFile(__dirname + "/public/home.html");
});

// Lancement du serveur
server.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
