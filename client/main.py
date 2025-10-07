import base64
import json
import nacl.signing
import os
import requests
import secrets
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Final
    
URL: Final = "https://localhost:7151/api/Verify"

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

print()
print('================ Digital Signature Validation ================')
print()

key_path = "../.ssh/private.pem"

# Allow user to specify a different key path
user_input = input(f"Enter the path to your PEM key file [{key_path}]: ").strip()
if user_input:
    key_path = user_input
    
if not os.path.isfile(key_path):
    raise FileNotFoundError(f"Key file not found at path: {key_path}")

# Extract the Ed25519 seed
seed = extract_ed25519_seed_from_pem(key_path)
if len(seed) != 32:
    raise ValueError("Extracted seed is not 32 bytes long, invalid Ed25519 key.")
print("Raw Ed25519 seed:", seed.hex())

# The payload to be sent
payload = {
    "message": "Hello, SpruceID!",
    "timestamp": time.time(),
    "nonce": secrets.token_urlsafe(32)
}

# Sign the payload
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

print()
print('================ Response ================')
print(response.status_code)
print(response.text)