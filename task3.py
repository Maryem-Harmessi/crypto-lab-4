import json
import base64
import hashlib
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# helpers 
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def fp(x: bytes) -> str:
    return hashlib.sha256(x).hexdigest()

def hkdf_derive(key_material: bytes, length: int, info: bytes, salt):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(key_material)

def header_ad(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")

def pub_bytes_x25519(pub: x25519.X25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def pub_from_bytes_x25519(b: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(b)

def x25519_priv_from_b64(s: str) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(b64d(s))


# load exported material
with open("bob_keys.json", "r", encoding="utf-8") as f:
    bob_keys = json.load(f)

with open("handshake_public.json", "r", encoding="utf-8") as f:
    pub = json.load(f)

bundle = pub["bob_bundle"]
alice_pub = pub["alice_pub"]

# Bob private keys
bob_ik_priv  = x25519_priv_from_b64(bob_keys["ik_private"])
bob_spk_priv = x25519_priv_from_b64(bob_keys["spk_private"])
bob_opk_priv = x25519_priv_from_b64(bob_keys["opk0_private"])

# Alice public keys
alice_ik_pub = pub_from_bytes_x25519(b64d(alice_pub["alice_ik_pub"]))
alice_ek_pub = pub_from_bytes_x25519(b64d(alice_pub["alice_ek_pub"]))

# recompute shared RK
dh1 = bob_spk_priv.exchange(alice_ik_pub)
dh2 = bob_ik_priv.exchange(alice_ek_pub)
dh3 = bob_spk_priv.exchange(alice_ek_pub)
dh4 = bob_opk_priv.exchange(alice_ek_pub)
ikm = dh1 + dh2 + dh3 + dh4

RK0 = hkdf_derive(ikm, length=32, info=b"lab4-x3dh", salt=b"\x00" * 32)
print("Loaded X3DH -> RK fingerprint:", fp(RK0))


# Double Ratchet
def kdf_rk(rk: bytes, dh_out: bytes):
    out = hkdf_derive(key_material=dh_out, length=64, info=b"dr-rk", salt=rk)
    return out[:32], out[32:]

def kdf_ck(ck: bytes):
    out = hkdf_derive(key_material=ck, length=64, info=b"dr-ck", salt=None)
    return out[:32], out[32:]

def new_state(name: str, RK: bytes, DHs_priv: x25519.X25519PrivateKey, DHr_pub_bytes: bytes, CKs: bytes, CKr: bytes):
    return {
        "name": name,
        "RK": RK,
        "DHs_priv": DHs_priv,
        "DHs_pub_bytes": pub_bytes_x25519(DHs_priv.public_key()),
        "DHr_pub_bytes": DHr_pub_bytes,
        "CKs": CKs,
        "CKr": CKr,
        "Ns": 0,
        "Nr": 0,
        "PN": 0,
        "SKIPPED": {}
    }

def skip_message_keys(state, until_n: int):
    while state["Nr"] < until_n:
        state["CKr"], mk = kdf_ck(state["CKr"])
        state["SKIPPED"][(state["DHr_pub_bytes"], state["Nr"])] = mk
        state["Nr"] += 1

def dh_ratchet(state, received_dh_pub_bytes: bytes):
    state["PN"] = state["Ns"]
    state["Ns"] = 0
    state["Nr"] = 0

    state["DHr_pub_bytes"] = received_dh_pub_bytes
    dh_pub_obj = pub_from_bytes_x25519(received_dh_pub_bytes)

    dh1 = state["DHs_priv"].exchange(dh_pub_obj)
    state["RK"], state["CKr"] = kdf_rk(state["RK"], dh1)

    state["DHs_priv"] = x25519.X25519PrivateKey.generate()
    state["DHs_pub_bytes"] = pub_bytes_x25519(state["DHs_priv"].public_key())

    dh2 = state["DHs_priv"].exchange(dh_pub_obj)
    state["RK"], state["CKs"] = kdf_rk(state["RK"], dh2)

def encrypt_message(state, plaintext: bytes) -> dict:
    state["CKs"], mk = kdf_ck(state["CKs"])
    header = {"dh": b64e(state["DHs_pub_bytes"]), "pn": state["PN"], "n": state["Ns"]}
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(mk).encrypt(nonce, plaintext, header_ad(header))
    state["Ns"] += 1
    return {"header": header, "nonce": b64e(nonce), "ct": b64e(ct)}

def decrypt_message(state, msg: dict) -> bytes:
    header = msg["header"]
    recv_dh_pub_bytes = b64d(header["dh"])
    pn = int(header["pn"])
    n = int(header["n"])

    key = (recv_dh_pub_bytes, n)
    if key in state["SKIPPED"]:
        mk = state["SKIPPED"].pop(key)
        return ChaCha20Poly1305(mk).decrypt(b64d(msg["nonce"]), b64d(msg["ct"]), header_ad(header))

    if state["DHr_pub_bytes"] != recv_dh_pub_bytes:
        skip_message_keys(state, pn)
        dh_ratchet(state, recv_dh_pub_bytes)

    skip_message_keys(state, n)
    state["CKr"], mk = kdf_ck(state["CKr"])
    state["Nr"] += 1
    return ChaCha20Poly1305(mk).decrypt(b64d(msg["nonce"]), b64d(msg["ct"]), header_ad(header))

def force_sender_dh_rotation(state):
    dh_pub_obj = pub_from_bytes_x25519(state["DHr_pub_bytes"])
    state["PN"] = state["Ns"]
    state["Ns"] = 0

    state["DHs_priv"] = x25519.X25519PrivateKey.generate()
    state["DHs_pub_bytes"] = pub_bytes_x25519(state["DHs_priv"].public_key())

    dh_out = state["DHs_priv"].exchange(dh_pub_obj)
    state["RK"], state["CKs"] = kdf_rk(state["RK"], dh_out)


# init DR states from RK0
alice_dh_prv = x25519.X25519PrivateKey.generate()
bob_dh_prv   = x25519.X25519PrivateKey.generate()

alice_dh_pub_bytes = pub_bytes_x25519(alice_dh_prv.public_key())
bob_dh_pub_bytes   = pub_bytes_x25519(bob_dh_prv.public_key())

ck_a2b = hkdf_derive(RK0, length=32, info=b"init-a2b", salt=None)
ck_b2a = hkdf_derive(RK0, length=32, info=b"init-b2a", salt=None)

alice_state = new_state("Alice", RK0, alice_dh_prv, bob_dh_pub_bytes, CKs=ck_a2b, CKr=ck_b2a)
bob_state   = new_state("Bob",   RK0, bob_dh_prv,   alice_dh_pub_bytes, CKs=ck_b2a, CKr=ck_a2b)

print("\n--- Task 3 demo ---")
m0 = encrypt_message(alice_state, b"msg0 from Alice")
m1 = encrypt_message(alice_state, b"msg1 from Alice")

print("Out-of-order: deliver m1 then m0")
print("Bob decrypted:", decrypt_message(bob_state, m1), decrypt_message(bob_state, m0))

r0 = encrypt_message(bob_state, b"reply0 from Bob")
print("Bidirectional: Alice decrypted:", decrypt_message(alice_state, r0))

force_sender_dh_rotation(alice_state)
m2 = encrypt_message(alice_state, b"after DH ratchet (Alice)")
print("DH ratchet: Bob decrypted:", decrypt_message(bob_state, m2))

print("\nSUCCESS: Task 3 complete.")
