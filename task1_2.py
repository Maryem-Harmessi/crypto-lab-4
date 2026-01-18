from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import json
import base64
import hashlib


# Helpers
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")
def b64d(s: str) -> bytes:
    return base64.b64decode(s)
def hkdf_derive(key_material: bytes, length: int, info: bytes, salt: bytes | None) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(key_material)
def fp(x: bytes) -> str:
    return hashlib.sha256(x).hexdigest()

# BOB Generate Keys
# Signing identity (Ed25519) for SPK signature
ik_sign_private = ed25519.Ed25519PrivateKey.generate()
ik_sign_public = ik_sign_private.public_key()
ik_sign_public_bytes = ik_sign_public.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# DH identity (X25519)
ik_private = x25519.X25519PrivateKey.generate()
ik_public = ik_private.public_key()
ik_public_bytes = ik_public.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Generate signed prekey pair
spk_private = x25519.X25519PrivateKey.generate()

spk_public = spk_private.public_key()

spk_public_bytes = spk_public.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

spk_signature = ik_sign_private.sign(spk_public_bytes)

try:
    ik_sign_public.verify(spk_signature, spk_public_bytes)
    print("SPK signature verified")
except InvalidSignature:
    print("SPK signature failed")
    raise

# Generate one time prekeys 
opk_num=4 
opk_public_bytes_list = []
opk_private_keys = []

for i in range(opk_num):
    opk_private = x25519.X25519PrivateKey.generate()
    opk_public = opk_private.public_key()
    opk_public_bytes = opk_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    opk_private_keys.append(opk_private)
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

print("Prekey bundle exported.")


# ALICE 
bob_ik_pub_bytes  = b64d(bundle["IK_pub"])
bob_spk_pub_bytes = b64d(bundle["SPK_pub"])
bob_opk_pub_bytes = b64d(bundle["OPK_pub_list"][0])

bob_ik_pub  = x25519.X25519PublicKey.from_public_bytes(bob_ik_pub_bytes)
bob_spk_pub = x25519.X25519PublicKey.from_public_bytes(bob_spk_pub_bytes)
bob_opk_pub = x25519.X25519PublicKey.from_public_bytes(bob_opk_pub_bytes)

# alice generate keys
alice_ik_prv = x25519.X25519PrivateKey.generate()
alice_ik_pub = alice_ik_prv.public_key()
alice_ik_pub_bytes = alice_ik_prv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

alice_ek_prv = x25519.X25519PrivateKey.generate()
alice_ek_pub = alice_ek_prv.public_key()
alice_ek_pub_bytes = alice_ek_prv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

#DH ALICE Side
dh1a = alice_ik_prv.exchange(bob_spk_pub)
dh2a = alice_ek_prv.exchange(bob_ik_pub)
dh3a = alice_ek_prv.exchange(bob_spk_pub)
dh4a = alice_ek_prv.exchange(bob_opk_pub)
ikm_a= dh1a+dh2a+dh3a+dh4a
print(len(dh1a), len(dh2a), len(dh3a), len(dh4a))
#alice root key 
rk_a = hkdf_derive(ikm_a, length=32, info=b"lab4-x3dh", salt=b"\x00" * 32)
# ck and mk 
ckmk_a = hkdf_derive(rk_a, length=64, info=b"lab4-chain", salt=None)
ck_a = ckmk_a[:32]
mk_a = ckmk_a[32:]

#DH Bob side
dh1b = spk_private.exchange(alice_ik_pub)
dh2b = ik_private.exchange(alice_ek_pub)
dh3b = spk_private.exchange(alice_ek_pub)
dh4b = opk_private_keys[0].exchange(alice_ek_pub)

print(len(dh1b), len(dh2b), len(dh3b), len(dh4b))

ikm_b = dh1b + dh2b + dh3b + dh4b

rk_b = hkdf_derive(ikm_b, length=32, info=b"lab4-x3dh", salt=b"\x00" * 32)

ckmk_b = hkdf_derive(rk_b, length=64, info=b"lab4-chain", salt=None)
ck_b = ckmk_b[:32]
mk_b = ckmk_b[32:]

print("\n=== Fingerprints (should match) ===")
print("RK Alice:", fp(rk_a))
print("RK Bob  :", fp(rk_b))
print("CK Alice:", fp(ck_a))
print("CK Bob  :", fp(ck_b))
print("MK Alice:", fp(mk_a))
print("MK Bob  :", fp(mk_b))

assert rk_a == rk_b, "RK mismatch"
assert ck_a == ck_b, "CK mismatch"
assert mk_a == mk_b, "MK mismatch"

print("\nSUCCESS: Both sides derived identical RK/CK/MK.")

def x25519_priv_to_b64(key: x25519.X25519PrivateKey) -> str:
    return b64e(key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ))

def ed25519_priv_to_b64(key: ed25519.Ed25519PrivateKey) -> str:
    return b64e(key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ))

bob_secret = {
    "ik_private": x25519_priv_to_b64(ik_private),
    "spk_private": x25519_priv_to_b64(spk_private),
    "opk0_private": x25519_priv_to_b64(opk_private_keys[0]),
    "ik_sign_private": ed25519_priv_to_b64(ik_sign_private),
}

with open("bob_keys.json", "w", encoding="utf-8") as f:
    json.dump(bob_secret, f, indent=2)

print("Exported bob_keys.json (PRIVATE)")

handshake_public = {
    "bob_bundle": bundle,  
    "alice_pub": {
        "alice_ik_pub": b64e(alice_ik_pub_bytes),
        "alice_ek_pub": b64e(alice_ek_pub_bytes),
    }
}

with open("handshake_public.json", "w", encoding="utf-8") as f:
    json.dump(handshake_public, f, indent=2)

print("Exported handshake_public.json (PUBLIC)")