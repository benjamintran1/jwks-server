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
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv

#load environmental variables in python
load_dotenv()

hostName = "localhost"
serverPort = 8080
db_filename = "totally_not_my_privateKeys.db"

print(os.environ.get('NOT_MY_KEY'))
AES_KEY2 = os.environ.get('NOT_MY_KEY')
AES_KEY = get_random_bytes(32)

def encrypt(plaintext, key):
    # Create an AES cipher object with the key and AES.MODE_ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    # Pad the plaintext and encrypt it
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext
 
def decrypt(ciphertext, key):
    # Create an AES cipher object with the key and AES.MODE_ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    # Decrypt the ciphertext and remove the padding
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data

# open database if exists. If doesn't then create the database
def open_db(filename):
    # Establish connection to the SQLite database
    conn = sqlite3.connect(filename)
    cursor = conn.cursor()

    # Create the 'keys' table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
                   kid INTEGER PRIMARY KEY AUTOINCREMENT, 
                   key BLOB NOT NULL, exp INTEGER NOT NULL
                   )''')


    # Create the 'users' table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP      
        )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,  
        FOREIGN KEY(user_id) REFERENCES users(id)
        )''')

    conn.commit()
    return conn

def table_exists(conn, table_name):
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cursor.fetchone() is not None

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
    encrypted_data = encrypt(key_data.encode('utf-8'), AES_KEY)
    conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_data, exp))
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
        content_length = int(self.headers['Content-Length']) # Get the size of data
        post_data = self.rfile.read(content_length) # Get the data
        post_data = json.loads(post_data.decode('utf-8'))  # Parse the JSON data

        conn = sqlite3.connect(db_filename)
        cursor = conn.cursor()

        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": int(time.time() + 3600)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = int(time.time() - 3600)
            ''' LOGGING USER INFORMATION '''


            # Log request details into auth_logs table
            ip_address = self.client_address[0]  # Extracting client IP address
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')  # Current timestamp
            
            user_id = 1

            # You may need to extract user_id based on your application logic
            # For example, if you have user authentication, you can retrieve user_id based on the authenticated user

            # Insert request details into auth_logs table
            conn.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)",
                        (ip_address, timestamp, user_id))
            conn.commit()


            ''' END OF LOGGING '''
            # if expired, get from database an expired key, if not expired, get a non expired key
            if 'expired' in params:
                key_data = retrieve_expired_key(db_conn)
            else:
                key_data = retrieve_unexpired_key(db_conn)

            if key_data is None:
                self.send_response(500)
                self.end_headers()
                return

            # Sign JWT with loaded private key
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
        elif parsed_path.path == "/register":
            # Take user registration details
            username = post_data.get('username')
            email = post_data.get('email')
            if not (username and email):
                self.send_response(400) # bad request
                self. end_headers()
                return
            password = str(uuid.uuid4())
            print(f"{password}")
            # hashed_password = hashlib.sha256(password.encode()).hexdigest()[:36]
            hashed_password = str(uuid.uuid4())
            print(f"after hashing, pw = {hashed_password}")

            # Insert user registration details into the database
            conn.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", (username, email, password))
            conn.commit()

            # Return password to the user in JSON format
            response_data = {"password": hashed_password}
            response_body = json.dumps(response_data)
            print(f"{username} {email} {password} ")

            
            
            self.send_response(201)  # Created
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(response_body.encode('utf-8'))
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
        conn = sqlite3.connect(db_filename)
        store_key(db_conn, pem.decode('utf-8'), int(time.time()))  # Store the current key with current time
        store_key(db_conn, expired_pem.decode('utf-8'), int(time.time() - 3600))  # Store the expired key with 1 hour ago
           
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server Closed")
