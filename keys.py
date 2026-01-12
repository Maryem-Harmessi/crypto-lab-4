from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

#generate iidentity key pair
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

try:(
    ik_public.verify(spk_signature, spk_public_bytes)
    )
except:  print("signature failed")

print("Signed prekey generated")

# Generate one time prekeys 
opk_num=4 
opk_private_keys = []
opk_public_bytes_list = []

for i in range(opk_num):
    opk_private = ed25519.Ed25519PrivateKey.generate()
    opk_public = opk_private.public_key()

    opk_public_bytes = opk_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    opk_private_keys.append(opk_private)
    opk_public_bytes_list.append(opk_public_bytes)

print(f"OPKs generated: {len(opk_public_bytes_list)}")
