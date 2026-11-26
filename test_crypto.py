"""
test_crypto.py - local tests for crypto_utils.py (no network).

The spec asks us to test the crypto functions before adding sockets.
Run:  python test_crypto.py
"""

import time
import base64

import crypto_utils as cu


def make_header(sender="alice", recipient="bob", num=1):
    return {"from": sender, "to": recipient, "msg_num": num, "timestamp": int(time.time())}


def expect_fail(label, packet, recv_priv, send_pub):
    try:
        cu.decrypt_and_verify(packet, recv_priv, send_pub)
    except cu.SecurityError as e:
        print(f"  PASS  {label}: rejected ({e})")
        return
    raise AssertionError(f"{label}: should have been rejected")


def flip_byte(b64_text, index=0):
    raw = bytearray(base64.b64decode(b64_text))
    raw[index] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def main():
    print("Generating test keys for alice, bob, carol...")
    a_priv, a_pub = cu.generate_keypair()
    b_priv, b_pub = cu.generate_keypair()
    c_priv, c_pub = cu.generate_keypair()

    # --- Test 1: normal round trip ---
    print("\n[Test 1] Normal message alice -> bob")
    pkt = cu.encrypt_and_sign("hello bob", a_priv, b_pub, make_header())
    assert cu.decrypt_and_verify(pkt, b_priv, a_pub) == "hello bob"
    print("  PASS  decrypted and verified")

    # --- Test 2: fresh key + nonce every time ---
    print("\n[Test 2] Same text twice gives different nonce/key/ciphertext")
    pkt2 = cu.encrypt_and_sign("hello bob", a_priv, b_pub, make_header(num=2))
    assert pkt["nonce"] != pkt2["nonce"]
    assert pkt["encrypted_key"] != pkt2["encrypted_key"]
    assert pkt["ciphertext"] != pkt2["ciphertext"]
    print("  PASS  nothing reused")

    # --- Test 3: tampering with each signed field ---
    print("\n[Test 3] Change each signed field")
    tampered = {
        "ciphertext byte flipped": {"ciphertext": flip_byte(pkt["ciphertext"])},
        "nonce changed": {"nonce": flip_byte(pkt["nonce"])},
        "encrypted key changed": {"encrypted_key": flip_byte(pkt["encrypted_key"], 5)},
        "sender changed": {"from": "carol"},
        "recipient changed": {"to": "carol"},
        "msg number changed": {"msg_num": 99},
        "timestamp changed": {"timestamp": pkt["timestamp"] + 60},
    }
    for label, change in tampered.items():
        expect_fail(label, {**pkt, **change}, b_priv, a_pub)

    # --- Test 4: wrong recipient (message for bob opened by carol) ---
    print("\n[Test 4] Carol tries to read bob's message")
    expect_fail("wrong recipient", pkt, c_priv, a_pub)

    # --- Test 5: carol forges a message pretending to be alice ---
    print("\n[Test 5] Carol signs with her own key but claims to be alice")
    forged = cu.encrypt_and_sign("send money", c_priv, b_pub, make_header(sender="alice"))
    expect_fail("forged sender", forged, b_priv, a_pub)

    # --- Test 6: key save/load with password ---
    print("\n[Test 6] Save and reload a password-protected key")
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        cu.save_keypair(a_priv, "alice", b"pw123", d)
        loaded = cu.load_private_key("alice", b"pw123", d)
        assert cu.fingerprint(loaded.public_key()) == cu.fingerprint(a_pub)
        try:
            cu.load_private_key("alice", b"wrong", d)
            raise AssertionError("wrong password should fail")
        except ValueError:
            pass
    print("  PASS  right password loads, wrong password refused")

    print("\nAll crypto tests passed.")


if __name__ == "__main__":
    main()
