from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import time
import sqlite3
import os

hostName = "localhost"
serverPort = 8080
db_filename = "totally_not_my_privateKeys.db"

# open database if exists. If doesn't then create the database
def open_db(filename):
    # Create SQLite database
    db_exists = os.path.exists(filename)
    conn = sqlite3.connect(filename)
    if not db_exists:
        # If the database file did not exist, create the necessary tables
        conn.execute("CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp REAL NOT NULL)")
    return conn

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()


def int_to_base64(value):
    # Convert an integer to a Base64URL-encoded string
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def store_key(conn, key_data, exp):
    # Store key to database
    conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_data, exp))
    conn.commit()

def retrieve_expired_key(conn):
    # retrieve expired key from database
    cursor = conn.execute("SELECT key FROM keys WHERE exp <= ?", (time.time(),))  # Use time.time() to get current time with milliseconds
    row = cursor.fetchone()
    # check if row is not empty and return first element. If empty then don't retrieve anything
    if row:
        return row[0]
    return None

def retrieve_unexpired_key(conn):
    # retrieve unexpired key
    expiration_time = time.time() + 3600  # Add 3600 seconds for 1 hour
    cursor = conn.execute("SELECT key FROM keys WHERE exp <= ?", (expiration_time,))
    row = cursor.fetchone()
    if row:
        return row[0]
    return None

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405) # Method not allowed
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405) # Method not allowed
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405) # Method not allowed
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405) # Method not allowed
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": time.time() + 3600
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = time.time() - 3600

            # if expired, get from database an expired key, if not expired, get a non expired key
            if 'expired' in params:
                key_data = retrieve_expired_key(db_conn)
            else:
                key_data = retrieve_unexpired_key(db_conn)

            if key_data is None:
                self.send_response(500)
                self.end_headers()
                return
            # Load private key from PEM-encoded string
            private_key = serialization.load_pem_private_key(key_data.encode(), password=None)

            # Sign JWT with loaded private key
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            # Retrieve all valid keys
            valid_keys = retrieve_unexpired_key(db_conn)
            
            valid_keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(valid_keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Running Server...")
    try:
        db_conn = open_db(db_filename) # connect to database
        store_key(db_conn, pem.decode('utf-8'), time.time())  # Store the current key with current time
        store_key(db_conn, expired_pem.decode('utf-8'), (time.time() - 3600))  # Store the expired key with 1 hour ago
           
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server Closed")