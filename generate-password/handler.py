import json
import random
import string
import io
import qrcode
import base64
import psycopg2
from datetime import datetime
from cryptography.fernet import Fernet

def generate_password(length=24):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.SystemRandom().choice(characters) for _ in range(length))

def generate_qrcode(data):
    qr = qrcode.make(data)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

def handle(event, context):
    try:
        with open('/var/openfaas/secrets/fernet-key', 'r') as f:
            FERNET_KEY = f.read().strip()

        with open('/var/openfaas/secrets/db-url', 'r') as f:
            DATABASE_URL = f.read().strip()

        if not FERNET_KEY or not DATABASE_URL:
            return {
                "statusCode": 500,
                "body": "Missing environment variables",
                "headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Allow-Methods": "*"
                }
            }

        fernet = Fernet(FERNET_KEY.encode())

        data = json.loads(event.body)
        username = data.get("username")

        if not username:
            return {
                "statusCode": 400,
                "body": "Missing 'username' in request body",
                "headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Allow-Methods": "*"
                }
            }

        # Generate passwort & qr code
        password = generate_password()
        encrypted_pw = fernet.encrypt(password.encode()).decode()
        qrcode_b64 = generate_qrcode(password)
        gendate = datetime.utcnow()

        # Connect bdd & insert data
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                MFA TEXT,
                gendate TIMESTAMP NOT NULL,
                expired BOOLEAN DEFAULT FALSE
            );
        """)
        cur.execute("""
            INSERT INTO users (username, password, gendate, expired)
            VALUES (%s, %s, %s, false)
            ON CONFLICT (username) DO UPDATE SET
                password = EXCLUDED.password,
                gendate = EXCLUDED.gendate,
                expired = false;
        """, (username, encrypted_pw, gendate))
        conn.commit()
        cur.close()
        conn.close()

        return {
            "statusCode": 200,
            "body": json.dumps({
                "username": username,
                "password": password,
                "password_qr": qrcode_b64
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
            "body": f"Internal error: {str(e)}",
            "headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Allow-Methods": "*"
                }
        }