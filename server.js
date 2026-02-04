const express = require("express");
const http = require("http");
const fetch = require("node-fetch");
const cookieParser = require("cookie-parser");

const app = express();
const server = http.createServer(app);

const SECRET_KEY = "TA_SECRET_KEY_ICI"; // ta clé secrète Cloudflare
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static("public")); // pour servir gate.html ou autres fichiers statiques

// Page gate
app.get("/", (req, res) => {
  if (req.cookies.captchaValidated) {
    res.send("Accès autorisé ✅"); // tu peux mettre ton vrai site ici si tu veux
  } else {
    res.sendFile(__dirname + "/public/gate.html"); // juste le Turnstile
  }
});

// Vérification Turnstile
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
      res.cookie("captchaValidated", "true", { maxAge: 24 * 60 * 60 * 1000 }); // 1 jour
      return res.json({ success: true });
    } else {
      return res.status(400).json({ success: false, message: "Échec du captcha" });
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

server.listen(PORT, () => console.log("Server running on port " + PORT));
