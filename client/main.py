import jwt
import requests
import json
import secrets
import time
import nacl.signing
import base64

from typing import Final
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
    
URL: Final = "https://localhost:7151/api/Verify"

def generate_timestamp():
    # Generate a current timestamp in seconds
    return time.time()
    
def generate_nonce():
    #Generate a secure nonce.
    return secrets.token_urlsafe(32)

def load_private_key(path):
    #Load a private key from a file.
    with open(path, 'rb') as key_file:
        raw_key = key_file.read()
    return raw_key

def extract_ed25519_seed_from_pem(keyfile_path):
    # Extract Ed25519 seed from a PEM file
    with open(keyfile_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    # For Ed25519, the private_bytes method returns the seed
    seed = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return seed

key_path = "../.ssh/private.pem"

seed = extract_ed25519_seed_from_pem(key_path)
print("Raw Ed25519 seed:", seed.hex())

# Convert the private key string to bytes (assuming it's base64 encoded)
#private_key_bytes = base64.b64decode(private_key)

# The payload to be sent
payload = {
    "message": "Hello, SpruceID!",
    "timestamp": generate_timestamp(),
    "nonce": generate_nonce()
}

payload_json = json.dumps(payload)
signing_key = nacl.signing.SigningKey(seed)
signed = signing_key.sign(payload_json.encode())
signature = base64.b64encode(signed.signature).decode()

# Prepare the request headers
headers = {
    "Content-Type": "application/json"
}
payload_with_signature = {"payload": payload, "signature": signature}

# POST the signed payload
response = requests.post(URL, headers=headers, json=payload_with_signature, verify=False)

print(response.status_code)
print(response.text)