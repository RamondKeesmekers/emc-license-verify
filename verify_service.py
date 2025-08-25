from flask import Flask, request, jsonify
import os
import jwt  # PyJWT
from jwt import InvalidTokenError

app = Flask(__name__)

AUTH = os.getenv("AUTH_TOKEN", "")

@app.before_request
def check_auth():
    # health is unauthenticated
    if request.path == "/health":
        return
    # simple static bearer header
    if AUTH and request.headers.get("Authorization", "") != f"Bearer {AUTH}":
        return jsonify(error="unauthorized"), 401

@app.get("/health")
def health():
    return "ok", 200

@app.post("/verify")
def verify():
    data = request.get_json(force=True) or {}
    token = data.get("token", "")
    pub   = data.get("public_key_pem", "")

    if not token or not pub:
        return jsonify(valid=False, error="missing_parameters"), 400

    try:
        # Strictly verify RS256 with the provided public key PEM
        payload = jwt.decode(token, pub, algorithms=["RS256"])
        return jsonify(valid=True, payload=payload), 200
    except InvalidTokenError as e:
        # Signature invalid, expired, bad format, etc.
        return jsonify(valid=False, error=str(e)), 200
