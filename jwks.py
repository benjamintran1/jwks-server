from flask import Flask, jsonify, request
from jwcrypto import jwk, jwt
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta


app = Flask(__name__)

# key pair dictionary
key_pairs = {}

def generate_key_pair(kid):
    # Get a key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Store the private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Store the public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Every key pair contains a private key, public key, and an expiration date
    key_pairs[kid] = {
        'private_key':private_pem,
        'public_key':public_pem,
        # expire in 1 hour
        'expiration':datetime.utcnow() + timedelta(minutes=1)
    }

# RESTful JWKS endpoint

@app.route('/jwks', methods=['GET'])
def jwks():
    if request.method != 'GET':
        return jsonify({'error': 'Method Not Allowed'}), 405 # HTTP Status 405, Method Not Allowed
    
    # Remove expired keys
    current_time = datetime.utcnow()
    expired_keys = [kid for kid, key_data in key_pairs.items() if key_data['expiration'] < current_time]
    for expired_key in expired_keys:
        del key_pairs[expired_key]
    generate_key_pair(str(len(key_pairs) + 1))

    # Exstract valid keys
    valid_keys = {kid: key_data['public_key'] for kid, key_data in key_pairs.items()}    
    
    jwks_data = {
        'keys': [
            {
                'kid': kid, # key ID
                'kty': 'RSA', # key type
                'alg': 'RS256', # algorithm type
                'use': 'sig', # public key use
                'n': key.decode('utf-8') # modulus for RSA public key
            } for kid, key in valid_keys.items()
        ]
    }
    # return all valid keys
    return jsonify(jwks_data), 200 # OK

# Auth endpoint 
@app.route('/auth', methods=['POST'])
def authenticate():
    
        # Get the expired parameter
    expired_param = request.args.get('expired')

    # If expired, give expired parameter, else return not expired token
    if expired_param:
        # Use the expired key pair
        key_data = key_pairs.get(expired_param)
        if not key_data:
            return jsonify({'error': 'Invalid key ID'}), 400
    else:
        # Use the latest valid key pair
        if not key_pairs:
            return jsonify({'error' : 'No valid keys available'}), 400
        valid_keys = {kid: key_data['expiration'] for kid, key_data in key_pairs.items()}
        latest_valid_key = max(valid_keys, key=valid_keys.get)
        key_data = key_pairs[latest_valid_key]

    # Create JWT
    claims = {
        'sub': 'JWT',
        'exp': int((datetime.utcnow() + timedelta(minutes=1)).timestamp()),  # expire in a minute
    }

    # Sign the JWT
    key = jwk.JWK.from_pem(key_data['private_key'])
    token = jwt.JWT(header={"alg": "RS256", "kid": latest_valid_key}, claims=claims)
    token.make_signed_token(key)

    return jsonify({'token': token.serialize()}), 200

# run on port 8080
if __name__ == '__main__':
    
    app.run(port=8080, debug=False)
