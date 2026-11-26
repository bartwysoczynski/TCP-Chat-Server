"""
crypto_utils.py - reusable crypto module for the secure chat.

This is the provided sample code (secure_message.py), reorganized into
functions the client can call. Nothing here touches the network.

  PART 1  Shared settings + base64 helpers
  PART 2  Key management (generate, save, load RSA keys)
  PART 3  Signed header (what the signature covers)
  PART 4  Encrypt + sign   (sender side)
  PART 5  Verify + decrypt (receiver side)
"""

import os
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag


# ============================================================
# PART 1: Shared settings + base64 helpers
# ============================================================

RSA_KEY_SIZE = 2048     # spec: at least 2048 bits
SEPARATOR = "|"         # joins the header fields before hashing

# Same padding settings as the sample code
OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


class SecurityError(Exception):
    """Raised when a message fails a check. The text says why."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


# ============================================================
# PART 2: Key management
# ============================================================

def generate_keypair():
    """Make a fresh 2048-bit RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    return private_key, private_key.public_key()


def save_keypair(private_key, name: str, password: bytes, key_dir: str = "keys"):
    """Save keys as PEM. The private key is encrypted with the password."""
    os.makedirs(key_dir, exist_ok=True)
    priv_path = os.path.join(key_dir, f"{name}_private.pem")
    pub_path = os.path.join(key_dir, f"{name}_public.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        ))
    # keep the private key readable by the owner only
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass  # Windows ignores this, that's fine

    with open(pub_path, "wb") as f:
        f.write(public_key_to_pem(private_key.public_key()).encode())
    return priv_path, pub_path


def load_private_key(name: str, password: bytes, key_dir: str = "keys"):
    """Load our private key. A wrong password raises ValueError."""
    with open(os.path.join(key_dir, f"{name}_private.pem"), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def public_key_to_pem(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def public_key_from_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def fingerprint(public_key) -> str:
    """Short SHA-256 fingerprint so users can compare keys out of band."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    h = hashlib.sha256(der).hexdigest()[:32]
    return ":".join(h[i:i + 4] for i in range(0, len(h), 4))


# ============================================================
# PART 3: Signed header
# ------------------------------------------------------------
# Change from the sample: the sample only signed the message.
# Here we sign sender, recipient, message number, timestamp,
# encrypted key, nonce and ciphertext, in that order, joined
# with "|". Changing any one of them breaks the signature.
# ============================================================

def signed_digest(sender, recipient, msg_num, timestamp,
                  encrypted_key_b64, nonce_b64, ciphertext_b64) -> bytes:
    parts = [sender, recipient, str(msg_num), str(timestamp),
             encrypted_key_b64, nonce_b64, ciphertext_b64]
    joined = SEPARATOR.join(parts).encode("utf-8")
    return hashlib.sha256(joined).digest()


# ============================================================
# PART 4: Encrypt + sign (sender side)
# ============================================================

def encrypt_and_sign(plaintext: str, sender_private_key, recipient_public_key, header: dict) -> dict:
    """
    header needs: from, to, msg_num, timestamp
    Returns the full chat packet (everything base64, ready for JSON).
    """
    data = plaintext.encode("utf-8")

    # 4a. Brand-new AES-256 key and 12-byte nonce for EVERY message
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, None)

    # 4b. Lock the AES key so only the recipient can open it (RSA-OAEP)
    encrypted_key = recipient_public_key.encrypt(aes_key, OAEP)

    ek, nn, ct = b64e(encrypted_key), b64e(nonce), b64e(ciphertext)

    # 4c. Hash header + encrypted data, then sign that hash (RSA-PSS)
    digest = signed_digest(header["from"], header["to"], header["msg_num"],
                           header["timestamp"], ek, nn, ct)
    signature = sender_private_key.sign(digest, PSS, utils.Prehashed(hashes.SHA256()))

    return {
        "type": "chat",
        "from": header["from"],
        "to": header["to"],
        "msg_num": header["msg_num"],
        "timestamp": header["timestamp"],
        "encrypted_key": ek,
        "nonce": nn,
        "ciphertext": ct,
        "signature": b64e(signature),
    }


# ============================================================
# PART 5: Verify + decrypt (receiver side)
# ------------------------------------------------------------
# Order matters: verify the signature FIRST, then unwrap the
# AES key, then decrypt. Plaintext is only returned if every
# step passes; otherwise SecurityError says what went wrong.
# (The replay check on msg_num happens in the client, before
#  this function is called.)
# ============================================================

def decrypt_and_verify(packet: dict, recipient_private_key, sender_public_key) -> str:
    # 5a. Pull out the fields (bad base64 = tampered packet)
    try:
        encrypted_key = b64d(packet["encrypted_key"])
        nonce = b64d(packet["nonce"])
        ciphertext = b64d(packet["ciphertext"])
        signature = b64d(packet["signature"])
    except (KeyError, ValueError, TypeError):
        raise SecurityError("packet is malformed (missing field or bad base64)")

    # 5b. Check the signature over the header + encrypted data
    digest = signed_digest(packet["from"], packet["to"], packet["msg_num"],
                           packet["timestamp"], packet["encrypted_key"],
                           packet["nonce"], packet["ciphertext"])
    try:
        sender_public_key.verify(signature, digest, PSS, utils.Prehashed(hashes.SHA256()))
    except InvalidSignature:
        raise SecurityError(
            f"signature check FAILED - not really from '{packet['from']}', "
            "or the header/ciphertext was changed in transit")

    # 5c. Unwrap the AES key with our private key
    try:
        aes_key = recipient_private_key.decrypt(encrypted_key, OAEP)
    except ValueError:
        raise SecurityError("AES key could not be decrypted - this message "
                            "was not encrypted for us")

    # 5d. Decrypt (GCM also checks the ciphertext wasn't modified)
    try:
        data = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise SecurityError("AES-GCM decryption failed - ciphertext was tampered with")

    return data.decode("utf-8")
