const express = require("express");
const http = require("http");
const fetch = require("node-fetch");
const cookieParser = require("cookie-parser");
const path = require("path");
const app = express();
const server = http.createServer(app);

// Configuration
const TURNSTILE_SECRET_KEY = "0x4AAAAAACXtON1ce0GeOud1iJJ6Uve9U7U"; // Clé secrète Cloudflare Turnstile
const VALID_ACCESS_KEY = "0x4AAAAAACXtOLndFMBYimGK"; // Clé d'accès valide
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static("public")); // Servir les fichiers statiques (CSS, JS, images)

// Route principale - Gate d'accès
app.get("/", (req, res) => {
  // Vérifier si l'utilisateur est déjà authentifié
  if (req.cookies.accessGranted === "true") {
    // Si authentifié, servir le fichier index.html principal
    res.sendFile(path.join(__dirname, "public", "index.html"));
  } else {
    // Sinon, afficher la gate (elle est déjà dans index.html avec la logique côté client)
    res.sendFile(path.join(__dirname, "public", "index.html"));
  }
});

// Route de vérification de la clé d'accès + Turnstile
app.post("/verify-access", async (req, res) => {
  const { accessKey, "cf-turnstile-response": turnstileToken } = req.body;

  // 1. Vérifier que la clé d'accès et le token Turnstile sont présents
  if (!accessKey) {
    return res.status(400).json({ 
      success: false, 
      message: "Clé d'accès manquante" 
    });
  }

  if (!turnstileToken) {
    return res.status(400).json({ 
      success: false, 
      message: "Captcha Turnstile manquant" 
    });
  }

  try {
    // 2. Vérifier le Turnstile avec Cloudflare
    const turnstileResponse = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${TURNSTILE_SECRET_KEY}&response=${turnstileToken}`
    });

    const turnstileData = await turnstileResponse.json();

    // 3. Si le Turnstile échoue
    if (!turnstileData.success) {
      return res.status(400).json({ 
        success: false, 
        message: "Échec de la vérification Turnstile" 
      });
    }

    // 4. Vérifier la clé d'accès
    if (accessKey.trim() !== VALID_ACCESS_KEY) {
      return res.status(401).json({ 
        success: false, 
        message: "Clé d'accès invalide" 
      });
    }

    // 5. Tout est valide - créer un cookie d'authentification
    res.cookie("accessGranted", "true", { 
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 jours
      httpOnly: true, // Sécurisé contre XSS
      secure: process.env.NODE_ENV === "production", // HTTPS en production
      sameSite: "strict" // Protection CSRF
    });

    return res.json({ 
      success: true, 
      message: "Accès autorisé" 
    });

  } catch (err) {
    console.error("Erreur lors de la vérification:", err);
    return res.status(500).json({ 
      success: false, 
      message: "Erreur serveur lors de la vérification" 
    });
  }
});

// Route de déconnexion
app.post("/logout", (req, res) => {
  res.clearCookie("accessGranted");
  return res.json({ 
    success: true, 
    message: "Déconnexion réussie" 
  });
});

// Route de vérification du statut d'authentification
app.get("/check-auth", (req, res) => {
  const isAuthenticated = req.cookies.accessGranted === "true";
  return res.json({ 
    authenticated: isAuthenticated 
  });
});

// Route pour vérifier uniquement le Turnstile (optionnel - si besoin séparé)
app.post("/verify-turnstile", async (req, res) => {
  const token = req.body["cf-turnstile-response"];
  
  if (!token) {
    return res.status(400).json({ 
      success: false, 
      message: "Token Turnstile manquant" 
    });
  }

  try {
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${TURNSTILE_SECRET_KEY}&response=${token}`
    });

    const data = await response.json();

    if (data.success) {
      return res.json({ 
        success: true, 
        message: "Turnstile vérifié avec succès" 
      });
    } else {
      return res.status(400).json({ 
        success: false, 
        message: "Échec de la vérification Turnstile",
        errors: data["error-codes"] || []
      });
    }
  } catch (err) {
    console.error("Erreur Turnstile:", err);
    return res.status(500).json({ 
      success: false, 
      message: err.message 
    });
  }
});

// Gestion des erreurs 404
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    message: "Route non trouvée" 
  });
});

// Démarrage du serveur
server.listen(PORT, () => {
  console.log(`✅ Serveur démarré sur le port ${PORT}`);
  console.log(`🔑 Clé d'accès valide: ${VALID_ACCESS_KEY}`);
  console.log(`🌐 Accès: http://localhost:${PORT}`);
});

module.exports = app;
