import json
import io
import base64
import psycopg2
import pyotp
import qrcode
from datetime import datetime
from cryptography.fernet import Fernet

def generate_totp_secret():
    return pyotp.random_base32()

def generate_qrcode(data):
    qr = qrcode.make(data)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

def handle(event, context):
    # Var env
    with open('/var/openfaas/secrets/fernet-key', 'r') as f:
        FERNET_KEY = f.read().strip()

    with open('/var/openfaas/secrets/db-url', 'r') as f:
        DATABASE_URL = f.read().strip()

    # Check env
    if not FERNET_KEY or not DATABASE_URL:
        return {
            "statusCode": 500,
            "body": "Variables d'environnement manquantes",
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "*"
            }
        }

    # Init Fernet
    fernet = Fernet(FERNET_KEY.encode())

    # Read JSON
    try:
        payload = json.loads(event.body or "{}")
    except json.JSONDecodeError:
        return {
            "statusCode": 400,
            "body": "Corps de requête invalide (JSON attendu)",
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "*"
            }
        }

    username = payload.get("username")
    if not username:
        return {
            "statusCode": 400,
            "body": "'username' manquant",
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "*"
            }
        }

    try:
        # Generate TOTP secret & URI link 
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name="COFRAP"
        )

        # Encoding
        encrypted_secret = fernet.encrypt(secret.encode()).decode()

        # Generate QR code Base64
        qrcode_b64 = generate_qrcode(provisioning_uri)

        # Connect BDD
        conn = psycopg2.connect(DATABASE_URL)
        cur  = conn.cursor()

        # Update 'mfa' & 'gendate'
        cur.execute("""
            UPDATE users
            SET mfa     = %s,
                gendate = %s,
                expired = false
            WHERE username = %s
        """, (encrypted_secret, datetime.utcnow(), username))

        # Check existing user
        if cur.rowcount == 0:
            conn.rollback()
            cur.close()
            conn.close()
            return {
                "statusCode": 404,
                "body": json.dumps({"error": "User not found"}),
                "headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Allow-Methods": "*"
                }
            }

        # Validate
        conn.commit()
        cur.close()
        conn.close()

        # Return URI & QR code
        return {
            "statusCode": 200,
            "body": json.dumps({
                "username": username,
                "mfa_uri": provisioning_uri,
                "mfa_qr": qrcode_b64
            }),
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "*"
            }
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": f"Erreur interne : {str(e)}",
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "*"
            }
        }