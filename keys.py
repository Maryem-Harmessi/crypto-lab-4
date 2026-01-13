from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import json
import base64

# Helpers
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

# Generate identity key pair
ik_private = ed25519.Ed25519PrivateKey.generate()

ik_public = ik_private.public_key()

ik_public_bytes = ik_public.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

print("Identity Key generated")

# Generate signed prekey pair
spk_private = ed25519.Ed25519PrivateKey.generate()

spk_public = spk_private.public_key()

spk_public_bytes = spk_public.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

spk_signature = ik_private.sign(spk_public_bytes)

try:
    ik_public.verify(spk_signature, spk_public_bytes)
    print("SPK signature verified")
except InvalidSignature:
    print("SPK signature failed")
    raise

print("Signed prekey generated")

# Generate one time prekeys 
opk_num=4 
opk_private_keys = []
opk_public_bytes_list = []

for i in range(opk_num-1):
    opk_private = ed25519.Ed25519PrivateKey.generate()
    opk_public = opk_private.public_key()
    opk_public_bytes = opk_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    opk_public_bytes_list.append(opk_public_bytes)

# Encoding and bundling the prekey bundle
bundle = {
        "IK_pub": b64e(ik_public_bytes),
        "SPK_pub": b64e(spk_public_bytes),
        "SPK_sig": b64e(spk_signature),
        "OPK_pub_list": [b64e(x) for x in opk_public_bytes_list],
    }

# Export prekey bundle
with open("prekey_bundle.json", "w", encoding="utf-8") as f:
    json.dump(bundle, f, indent=2)

opk_private_keys.append(opk_private)
opk_public_bytes_list.append(opk_public_bytes)

print(f"OPKs generated: {len(opk_public_bytes_list)}")
