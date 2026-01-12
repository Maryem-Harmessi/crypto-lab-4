# Lab 4: Implementing End-to-End Encryption Using the Signal Protocol


## Environment Setup
* Checked if Python is already installed
```
python --version
```

* Created an isolated Python virtual environment.
* Installed the required cryptographic library (cryptography) compatible with the lab specifications.
* Verified the environment by importing the library and executing test scripts.


## Task 1 – Generate Identity and Prekey Material
* Identity Key Pair (IK):
Generated a long-term Ed25519 identity key pair used to authenticate prekeys.

* Signed Prekey Pair (SPK):
Generated a medium-term Ed25519 prekey pair.
The SPK public key was signed using the Identity Key private key, and the signature was verified to ensure authenticity.

* One-Time Prekeys (OPKs):
Generated a set of one-time prekey pairs intended for single use during initial key agreement.

*The script was executed to confirm successful key generation.

Acknowledgment: ChatGPT (GPT-5.2) was used as a supplementary tool for conceptual clarification and documentation support.