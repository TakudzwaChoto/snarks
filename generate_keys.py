from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import os

os.makedirs("keys", exist_ok=True)

# Generate Ed25519 keys
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Save keys in raw bytes format (not PEM)
with open("keys/ed25519_private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("keys/ed25519_public.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

print("Keys generated in ./keys/")