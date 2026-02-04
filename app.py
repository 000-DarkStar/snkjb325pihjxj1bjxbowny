from flask import Flask, request, redirect
import requests

app = Flask(__name__)
SECRET_KEY = "0x4AAAAAACXtON1ce0GeOud1iJJ6Uve9U7U"

@app.route("/verify-turnstile", methods=["POST"])
def verify_turnstile():
    token = request.form.get("cf-turnstile-response")
    if not token:
        return "Captcha manquant", 400

    resp = requests.post(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data={"secret": SECRET_KEY, "response": token}
    ).json()

    if resp.get("success"):
        # redirige vers ton vrai site
        return redirect("/index")  
    else:
        return "Échec du captcha", 400

@app.route("/index")
def home():
    return "<h1>Bienvenue sur le site</h1>"

if __name__ == "__main__":
    app.run(debug=True)
