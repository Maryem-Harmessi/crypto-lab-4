# Lab 4: Implementing End-to-End Encryption Using the Signal Protocol
## Environment Setup

Verified that Python was installed:

```python --version```




Created an isolated Python virtual environment to avoid dependency conflicts.

Installed the required cryptographic library compatible with the lab specifications:

```pip install cryptography```


Verified the environment by importing the library and running test scripts to ensure correct installation.

## Task 1 – Generate Identity and Prekey Material

**Identity Keys (IK):**

- Generated a long-term X25519 identity key pair for Diffie–Hellman key exchange.

- Generated a separate Ed25519 identity signing key pair used to authenticate prekeys.

**Signed Prekey (SPK):**

- Generated a medium-term X25519 signed prekey pair.

- Signed the SPK public key using the Ed25519 identity private key.

- Verified the signature locally to ensure the integrity and authenticity of the signed prekey.

**One-Time Prekeys (OPKs):**

- Generated multiple X25519 one-time prekey pairs intended for single-use during initial session establishment.

**Prekey Bundle Export:**

- Constructed a prekey bundle containing only public material:

  - Identity public key

  - Signed prekey public key

  - Signed prekey signature

  - One-time prekey public keys

- Exported the bundle as a JSON file for later retrieval by a communicating peer.

The script was executed successfully to confirm correct key generation and export.

## Task 2 – Simplified X3DH Handshake

- Loaded Bob’s exported prekey bundle.

- Generated Alice’s identity key and ephemeral key.

- Performed the four Diffie–Hellman computations defined by X3DH (DH1–DH4).

- Concatenated the DH outputs and applied HKDF to derive:

  - Root Key (RK)

  - Initial Chain Key (CK)

  - Initial Message Key (MK)

- Independently derived the same keys on both Alice and Bob sides.

- Verified correctness by comparing cryptographic fingerprints and asserting equality.

Successful execution confirmed that both parties derived identical shared secrets.

```python task1_2.py```

## Task 3 – Double Ratchet Mechanism

- Initialized the Double Ratchet state using the Root Key obtained from X3DH.

- Implemented:

  - DH Ratchet: updating the Root Key and chain keys when new Diffie–Hellman public keys are received.

  - Symmetric-Key Ratchet: deriving a fresh message key for each message.

  - Authenticated Encryption: encrypting messages using ChaCha20-Poly1305 with associated data.

  - Skipped Message Handling: storing and recovering message keys for out-of-order delivery.

- Demonstrated:

  - Out-of-order message decryption

  - Bidirectional encrypted communication

  - Correct state updates after a DH ratchet step

The task confirmed proper ratchet state evolution and forward secrecy.

```python task3.py```

## Task 4 – End-to-End Encrypted Communication

- Built a terminal-based chat application using sockets.

- Bob loaded his previously generated private keys and published prekey bundle.

- Alice retrieved Bob’s bundle and performed the X3DH handshake.

- Both sides derived identical root keys and initialized the ratchet state.

-Exchanged at least five encrypted messages in each direction.

- Verified successful decryption and message ordering during live communication.

The demo confirmed functional end-to-end encrypted communication using the Signal protocol design principles.

Open two separate terminals.

Terminal 1 (Bob – server)
```python task4.py bob```

Terminal 2 (Alice – client)
```python task4.py alice```

## Acknowledgment

ChatGPT (GPT-5.2) was used as a supplementary tool for conceptual clarification and documentation support.