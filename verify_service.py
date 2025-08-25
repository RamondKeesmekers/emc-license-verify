from flask import Flask, request, jsonify
import os
import jwt  # PyJWT
from jwt import InvalidTokenError

app = Flask(__name__)

AUTH = os.getenv("AUTH_TOKEN", "").strip()

@app.before_request
def check_auth():
    if request.path == "/health":
        return
    got = (request.headers.get("Authorization") or "").strip()
    # Accept "Bearer <token>" or raw token
    token = got
    if got.lower().startswith("bearer "):
        token = got.split(" ", 1)[1].strip()
    if AUTH and token != AUTH:
        return jsonify(error="unauthorized"), 401

@app.get("/health")
def health():
    return "ok", 200

def _normalize_pem(pem: str) -> str:
    """
    Accepts PEM with real newlines OR with literal '\n' sequences from JSON/props.
    Ensures correct BEGIN/END PUBLIC KEY block and real newlines.
    """
    s = (pem or "").strip()
    # Convert literal backslash-n into actual newlines
    s = s.replace("\r\n", "\n").replace("\\n", "\n").strip()
    # Optional: trim anything before/after the block
    begin = "-----BEGIN PUBLIC KEY-----"
    end   = "-----END PUBLIC KEY-----"
    if begin in s and end in s:
        s = s[s.index(begin): s.rindex(end) + len(end)]
    return s

@app.post("/verify")
def verify():
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify(valid=False, error="bad_json"), 200

    token = data.get("token", "")
    pub   = data.get("public_key_pem", "")
    if not token or not pub:
        return jsonify(valid=False, error="missing_parameters"), 400

    pub_norm = _normalize_pem(pub)

    try:
        # Verify strictly as RS256
        payload = jwt.decode(token, pub_norm, algorithms=["RS256"])
        return jsonify(valid=True, payload=payload), 200
    except InvalidTokenError as e:
        # Signature invalid, expired, wrong key, etc.
        return jsonify(valid=False, error=str(e)), 200
    except Exception as e:
        # Any other unexpected errors
        return jsonify(valid=False, error=f"server_error: {e}"), 200
