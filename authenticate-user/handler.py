import json
import psycopg2
import pyotp
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

def handle(event, context):
    # Var env
    with open('/var/openfaas/secrets/fernet-key', 'r') as f:
        key = f.read().strip()

    with open('/var/openfaas/secrets/db-url', 'r') as f:
        db = f.read().strip()

    if not key or not db:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Variables d'environnement manquantes"}),
            "headers": {
                "Content-Type":"application/json",
                "Access-Control-Allow-Origin":"*",
                "Access-Control-Allow-Headers":"*",
                "Access-Control-Allow-Methods":"*"
            }
        }

    # Parse JSON
    try:
        payload = json.loads(event.body or "{}")
    except json.JSONDecodeError:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "JSON invalide"}),
            "headers": {
                "Content-Type":"application/json",
                "Access-Control-Allow-Origin":  "*",
                "Access-Control-Allow-Headers":"*",
                "Access-Control-Allow-Methods":"*"
            }
        }

    username = payload.get("username")
    password = payload.get("password")
    code     = payload.get("code")
    if not all([username, password, code]):
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Username, Password et Code sont requis"}),
            "headers": {
                "Content-Type":"application/json",
                "Access-Control-Allow-Origin":"*",
                "Access-Control-Allow-Headers":"*",
                "Access-Control-Allow-Methods":"*"
            }
        }

    # Connect BDD
    try:
        conn = psycopg2.connect(db)
        cur  = conn.cursor()
        cur.execute(
            "SELECT password, mfa, gendate FROM users WHERE username=%s",
            (username,)
        )
        row = cur.fetchone()
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": f"Erreur DB: {str(e)}"}),
            "headers": {
                "Content-Type":"application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers":"*",
                "Access-Control-Allow-Methods":"*"
            }
        }

    if not row:
        return {
            "statusCode": 404,
            "body": json.dumps({"error":"Utilisateur non trouvé"}),
            "headers": {
                "Content-Type":"application/json",
                "Access-Control-Allow-Origin":"*",
                "Access-Control-Allow-Headers":"*",
                "Access-Control-Allow-Methods":"*"
            }
        }

    enc_pw, enc_mfa, gendate = row
    fernet = Fernet(key.encode())

    # Check expired credential
    if gendate + timedelta(days=180) < datetime.utcnow():
        cur.execute(
            "UPDATE users SET expired = true WHERE username = %s",
            (username,)
        )
        conn.commit()
        cur.close()
        conn.close()
        return {
            "statusCode": 401,
            "body": json.dumps({"error": "Identifiants expirés"}),
            "headers": {
                "Content-Type":"application/json",
                "Access-Control-Allow-Origin":"*",
                "Access-Control-Allow-Headers":"*",
                "Access-Control-Allow-Methods":"*"
            }
        }

    # Check password
    try:
        real_pw = fernet.decrypt(enc_pw.encode()).decode()
    except Exception:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Erreur mot de passe"}),
            "headers": {
                "Content-Type":"application/json",
                "Access-Control-Allow-Origin":"*",
                "Access-Control-Allow-Headers":"*",
                "Access-Control-Allow-Methods":"*"
            }
        }
    if real_pw != password:
        cur.close()
        conn.close()
        return {
            "statusCode": 401,
            "body": json.dumps({"error": "Mot de passe incorrect"}),
            "headers": {
                "Content-Type":"application/json",
                "Access-Control-Allow-Origin":"*",
                "Access-Control-Allow-Headers":"*",
                "Access-Control-Allow-Methods":"*"
            }
        }

    # Check TOTP
    try:
        secret = fernet.decrypt(enc_mfa.encode()).decode()
    except Exception:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Erreur TOTP"}),
            "headers": {
                "Content-Type":"application/json",
                "Access-Control-Allow-Origin":"*",
                "Access-Control-Allow-Headers":"*",
                "Access-Control-Allow-Methods":"*"
            }
        }
    if not pyotp.TOTP(secret).verify(code):
        cur.close()
        conn.close()
        return {
            "statusCode": 401,
            "body": json.dumps({"error": "Code 2FA invalide"}),
            "headers": {
                "Content-Type":"application/json",
                "Access-Control-Allow-Origin":"*",
                "Access-Control-Allow-Headers":"*",
                "Access-Control-Allow-Methods":"*"
            }
        }

    # Success
    cur.close()
    conn.close()
    return {
        "statusCode": 200,
        "body": json.dumps({"message": "Authentification réussie"}),
        "headers": {
            "Content-Type":"application/json",
            "Access-Control-Allow-Origin":"*",
            "Access-Control-Allow-Headers":"*",
            "Access-Control-Allow-Methods":"*"
        }
    }
