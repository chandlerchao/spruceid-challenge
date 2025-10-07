import jwt
import requests
import json
import secrets
import time
import nacl.signing
import base64

from typing import Final

URL: Final = "https://localhost:7151/api/Verify"

def generate_timestamp():
    # Generate a current timestamp in seconds
    return time.time()
    
def generate_nonce():
    #Generate a secure nonce.
    return secrets.token_urlsafe(32)

def load_private_key(path):
    #Load a private key from a file.
    with open(path, 'r') as key_file:
        return key_file.read()

# Main function to demonstrate signing a payload and sending it in an HTTP request.
key_path = input("Please enter the path to your key file: ")
print("You entered:", key_path)

# Load the private key
private_key = load_private_key(key_path)

# Convert the private key string to bytes (assuming it's base64 encoded)
private_key_bytes = base64.b64decode(private_key)

# The payload to be sent
payload = {
    "message": "Hello, SpruceID!",
    "timestamp": generate_timestamp(),
    "nonce": generate_nonce()
}

payload_json = json.dumps(payload)
signing_key = nacl.signing.SigningKey(private_key_bytes)
signed = signing_key.sign(payload_json.encode())
signature = base64.b64encode(signed.signature).decode()

# Prepare the request headers
headers = {
    "Content-Type": "application/json"
}
payload_with_signature = {**payload, "signature": signature}

# POST the signed payload
response = requests.post(URL, headers=headers, json=payload_with_signature)

print(response.status_code)
print(response.text)