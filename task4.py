import argparse
import json
import socket
import base64
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

def hkdf_derive(key_material: bytes, length: int, info: bytes, salt):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(key_material)

def pub_from_bytes_x25519(b: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(b)

def x25519_priv_from_b64(s: str) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(b64d(s))

def header_ad(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")

def send_json_line(sock: socket.socket, obj: dict):
    sock.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8"))

def recv_json_line(sock: socket.socket) -> dict:
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    line, _ = buf.split(b"\n", 1)
    return json.loads(line.decode("utf-8"))


# minimal ratchet for chat
def kdf_ck(ck: bytes):
    out = hkdf_derive(ck, length=64, info=b"task4-ck", salt=None)
    return out[:32], out[32:]

def init_chat_state(rk: bytes, am_alice: bool):
    ck_a2b = hkdf_derive(rk, length=32, info=b"task4-a2b", salt=None)
    ck_b2a = hkdf_derive(rk, length=32, info=b"task4-b2a", salt=None)
    if am_alice:
        return {"CKs": ck_a2b, "CKr": ck_b2a, "Ns": 0, "Nr": 0}
    else:
        return {"CKs": ck_b2a, "CKr": ck_a2b, "Ns": 0, "Nr": 0}

def encrypt_msg(state: dict, plaintext: bytes) -> dict:
    state["CKs"], mk = kdf_ck(state["CKs"])
    header = {"n": state["Ns"]}
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(mk).encrypt(nonce, plaintext, header_ad(header))
    state["Ns"] += 1
    return {"header": header, "nonce": b64e(nonce), "ct": b64e(ct)}

def decrypt_msg(state: dict, msg: dict) -> bytes:
    n = int(msg["header"]["n"])
    while state["Nr"] < n:
        state["CKr"], _ = kdf_ck(state["CKr"])
        state["Nr"] += 1
    state["CKr"], mk = kdf_ck(state["CKr"])
    state["Nr"] += 1
    return ChaCha20Poly1305(mk).decrypt(b64d(msg["nonce"]), b64d(msg["ct"]), header_ad(msg["header"]))


# RK computation
def compute_rk_alice(bundle: dict):
    bob_ik_pub  = pub_from_bytes_x25519(b64d(bundle["IK_pub"]))
    bob_spk_pub = pub_from_bytes_x25519(b64d(bundle["SPK_pub"]))
    bob_opk_pub = pub_from_bytes_x25519(b64d(bundle["OPK_pub_list"][0]))

    alice_ik_prv = x25519.X25519PrivateKey.generate()
    alice_ek_prv = x25519.X25519PrivateKey.generate()

    dh1 = alice_ik_prv.exchange(bob_spk_pub)
    dh2 = alice_ek_prv.exchange(bob_ik_pub)
    dh3 = alice_ek_prv.exchange(bob_spk_pub)
    dh4 = alice_ek_prv.exchange(bob_opk_pub)
    ikm = dh1 + dh2 + dh3 + dh4

    rk = hkdf_derive(ikm, length=32, info=b"lab4-x3dh", salt=b"\x00" * 32)

    alice_pub = {
        "alice_ik_pub": b64e(alice_ik_prv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )),
        "alice_ek_pub": b64e(alice_ek_prv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )),
    }
    return rk, alice_pub

def compute_rk_bob(bob_keys: dict, alice_pub: dict):
    bob_ik_priv  = x25519_priv_from_b64(bob_keys["ik_private"])
    bob_spk_priv = x25519_priv_from_b64(bob_keys["spk_private"])
    bob_opk_priv = x25519_priv_from_b64(bob_keys["opk0_private"])

    alice_ik_pub = pub_from_bytes_x25519(b64d(alice_pub["alice_ik_pub"]))
    alice_ek_pub = pub_from_bytes_x25519(b64d(alice_pub["alice_ek_pub"]))

    dh1 = bob_spk_priv.exchange(alice_ik_pub)
    dh2 = bob_ik_priv.exchange(alice_ek_pub)
    dh3 = bob_spk_priv.exchange(alice_ek_pub)
    dh4 = bob_opk_priv.exchange(alice_ek_pub)
    ikm = dh1 + dh2 + dh3 + dh4

    return hkdf_derive(ikm, length=32, info=b"lab4-x3dh", salt=b"\x00" * 32)


# roles 
def run_bob(host: str, port: int):
    with open("bob_keys.json", "r", encoding="utf-8") as f:
        bob_keys = json.load(f)

    with open("handshake_public.json", "r", encoding="utf-8") as f:
        pub = json.load(f)

    bundle = pub["bob_bundle"]

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind((host, port))
    srv.listen(1)
    conn, addr = srv.accept()
    print("[Bob] connected:", addr)

    # send Bob bundle
    send_json_line(conn, {"type": "bundle", "bundle": bundle})

    # receive Alice public keys
    msg = recv_json_line(conn)
    alice_pub = msg["alice_pub"]

    rk = compute_rk_bob(bob_keys, alice_pub)
    st = init_chat_state(rk, am_alice=False)
    print("[Bob] RK derived. Chat ready.")

    # receive 5 then send 5
    print("[Bob] waiting for 5 messages from Alice...")
    for _ in range(5):
        m = recv_json_line(conn)["payload"]
        pt = decrypt_msg(st, m)
        print("[Bob recv]", pt.decode(errors="replace"))

    print("[Bob] send 5 messages to Alice...")
    for i in range(1, 6):
        text = input(f"[Bob send {i}/5] > ").encode("utf-8")
        payload = encrypt_msg(st, text)
        send_json_line(conn, {"type": "chat", "payload": payload})

    conn.close()
    srv.close()
    print("[Bob] done.")

def run_alice(host: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print("[Alice] connected.")

    # receive bundle
    msg = recv_json_line(sock)
    bundle = msg["bundle"]

    rk, alice_pub = compute_rk_alice(bundle)
    st = init_chat_state(rk, am_alice=True)
    print("[Alice] RK derived. Chat ready.")

    # send alice pubs to bob
    send_json_line(sock, {"type": "alice_pub", "alice_pub": alice_pub})

    # send 5 then receive 5
    print("[Alice] send 5 messages to Bob...")
    for i in range(1, 6):
        text = input(f"[Alice send {i}/5] > ").encode("utf-8")
        payload = encrypt_msg(st, text)
        send_json_line(sock, {"type": "chat", "payload": payload})

    print("[Alice] waiting for 5 messages from Bob...")
    for _ in range(5):
        m = recv_json_line(sock)["payload"]
        pt = decrypt_msg(st, m)
        print("[Alice recv]", pt.decode(errors="replace"))

    sock.close()
    print("[Alice] done.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["bob", "alice"])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5050)
    args = ap.parse_args()

    if args.role == "bob":
        run_bob(args.host, args.port)
    else:
        run_alice(args.host, args.port)

if __name__ == "__main__":
    main()
