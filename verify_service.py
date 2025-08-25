from flask import Flask, request, jsonify
import os, jwt
from jwt import InvalidTokenError, InvalidAlgorithmError
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

AUTH = os.getenv("AUTH_TOKEN", "").strip()

@app.before_request
def check_auth():
    if request.path == "/health":
        return
    got = (request.headers.get("Authorization") or "").strip()
    # accept "Bearer <token>" or raw token
    token = got.split(" ", 1)[1].strip() if got.lower().startswith("bearer ") else got
    if AUTH and token != AUTH:
        return jsonify(error="unauthorized"), 401

@app.get("/health")
def health():
    return "ok", 200

def _normalize_pem(pem: str) -> str:
    s = (pem or "").strip()
    # turn literal \n into real newlines; normalize CRLF
    s = s.replace("\r\n", "\n").replace("\\n", "\n").strip()
    # keep only the relevant block if present
    begin_end = [
        ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"),
        ("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"),
        ("-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"),
    ]
    for begin, end in begin_end:
        if begin in s and end in s:
            return s[s.index(begin): s.rindex(end) + len(end)]
    return s

def _load_rsa_public_key(pem: str):
    """
    Accepts PUBLIC KEY, RSA PUBLIC KEY, or CERTIFICATE PEM.
    Returns a cryptography RSAPublicKey or raises ValueError.
    """
    err_msgs = []

    # Try as direct public key
    try:
        key = load_pem_public_key(pem.encode("utf-8"))
        if isinstance(key, rsa.RSAPublicKey):
            return key
        err_msgs.append("loaded key is not RSA")
    except Exception as e:
        err_msgs.append(f"public_key_parse_error: {e}")

    # Try as certificate
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return key
        err_msgs.append("cert public key is not RSA")
    except Exception as e:
        err_msgs.append(f"cert_parse_error: {e}")

    raise ValueError("; ".join(err_msgs))

@app.post("/verify")
def verify():
    # parse body
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify(valid=False, error="bad_json"), 200

    token = data.get("token", "")
    pub   = data.get("public_key_pem", "")
    if not token or not pub:
        return jsonify(valid=False, error="missing_parameters"), 400

    # sanity: header alg must be RS256
    try:
        hdr = jwt.get_unverified_header(token)
        if (hdr.get("alg") or "").upper() != "RS256":
            return jsonify(valid=False, error="unexpected_alg"), 200
    except Exception as e:
        return jsonify(valid=False, error=f"bad_header: {e}"), 200

    pem_norm = _normalize_pem(pub)
    try:
        key = _load_rsa_public_key(pem_norm)
    except ValueError as e:
        return jsonify(valid=False, error=f"key_load_error: {e}"), 200

    # verify
    try:
        payload = jwt.decode(token, key, algorithms=["RS256"])
        return jsonify(valid=True, payload=payload), 200
    except InvalidAlgorithmError as e:
        return jsonify(valid=False, error=f"alg_not_supported: {e}"), 200
    except InvalidTokenError as e:
        return jsonify(valid=False, error=str(e)), 200
    except Exception as e:
        return jsonify(valid=False, error=f"server_error: {e}"), 200
