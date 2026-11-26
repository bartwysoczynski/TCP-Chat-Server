"""
client.py - chat client for the secure chat.

All encryption, signing, verifying and decrypting happens here,
using crypto_utils.py. The server only ever sees ciphertext.

  PART 1  Key setup (generate or load, password protected)
  PART 2  Connect + register with the server
  PART 3  Public-key lookup + cache
  PART 4  Sending (encrypt + sign + send)
  PART 5  Receiving thread (so you can keep typing)
  PART 6  Replay protection + verify/decrypt incoming
  PART 7  Command loop

Run:  python client.py alice
"""

import argparse
import getpass
import json
import os
import queue
import socket
import sys
import threading
import time

import crypto_utils as cu


KEY_DIR = "keys"


class ChatClient:
    def __init__(self, username, host, port):
        self.username = username
        self.host, self.port = host, port
        self.sock = None
        self.send_lock = threading.Lock()

        self.key_cache = {}            # username -> public key object
        self.key_replies = {}          # username -> PEM or None (unknown user)
        self.key_cond = threading.Condition()

        self.inbox = queue.Queue()     # incoming chat packets waiting to be checked
        self.running = True

    # ============================================================
    # PART 1: Key setup
    # ------------------------------------------------------------
    # First run: make a key pair and save it under a password.
    # Later runs: load it back with the same password.
    # The private key never leaves this machine.
    # ============================================================

    def load_or_create_keys(self):
        priv_path = os.path.join(KEY_DIR, f"{self.username}_private.pem")

        if os.path.exists(priv_path):
            for _ in range(3):
                pw = getpass.getpass(f"Password for {self.username}'s private key: ").encode()
                try:
                    self.private_key = cu.load_private_key(self.username, pw, KEY_DIR)
                    break
                except ValueError:
                    print("Wrong password.")
            else:
                sys.exit("Too many wrong passwords.")
            print(f"Loaded existing keys from {KEY_DIR}/")
        else:
            print(f"No keys for {self.username} yet - making a new 2048-bit RSA key pair.")
            while True:
                pw = getpass.getpass("Choose a password to protect your private key: ").encode()
                if pw and pw == getpass.getpass("Type it again: ").encode():
                    break
                print("Passwords empty or didn't match, try again.")
            self.private_key, _ = cu.generate_keypair()
            cu.save_keypair(self.private_key, self.username, pw, KEY_DIR)
            print(f"Saved {KEY_DIR}/{self.username}_private.pem (encrypted) "
                  f"and {self.username}_public.pem")

        self.public_key = self.private_key.public_key()
        print(f"Your key fingerprint: {cu.fingerprint(self.public_key)}")

        # message counter + replay table survive restarts
        self.counter_file = os.path.join(KEY_DIR, f"{self.username}_counter.txt")
        self.seen_file = os.path.join(KEY_DIR, f"{self.username}_seen.json")
        self.next_msg_num = int(open(self.counter_file).read()) if os.path.exists(self.counter_file) else 1
        self.highest_seen = json.load(open(self.seen_file)) if os.path.exists(self.seen_file) else {}

    # ============================================================
    # PART 2: Connect + register
    # ============================================================

    def send_json(self, obj):
        with self.send_lock:
            self.sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))

    def connect_and_register(self):
        self.sock = socket.create_connection((self.host, self.port))
        self.reader = self.sock.makefile("r", encoding="utf-8")

        # only the PUBLIC key is ever sent
        self.send_json({"type": "register", "username": self.username,
                        "public_key": cu.public_key_to_pem(self.public_key)})
        reply = json.loads(self.reader.readline() or "{}")
        if reply.get("type") != "register_ok":
            sys.exit(f"Registration failed: {reply.get('message', 'no reply')}")
        print(f"Connected to {self.host}:{self.port} as '{self.username}'")

    # ============================================================
    # PART 3: Public-key lookup + cache
    # ------------------------------------------------------------
    # Ask the server once, then keep the key. The receive thread
    # drops the server's answer into key_replies and wakes us up.
    # ============================================================

    def get_public_key(self, user):
        if user == self.username:
            return self.public_key
        if user in self.key_cache:
            return self.key_cache[user]

        with self.key_cond:
            self.key_replies.pop(user, None)
            self.send_json({"type": "key_request", "username": user})
            got = self.key_cond.wait_for(lambda: user in self.key_replies, timeout=5)
            pem = self.key_replies.pop(user, None) if got else None

        if not pem:
            return None
        key = cu.public_key_from_pem(pem)
        self.key_cache[user] = key
        self.show(f"(got {user}'s public key, fingerprint {cu.fingerprint(key)})")
        return key

    # ============================================================
    # PART 4: Sending
    # ============================================================

    def send_chat(self, to, text, claim_from=None):
        recipient_key = self.get_public_key(to)
        if recipient_key is None:
            self.show(f"[!] '{to}' is not online / unknown")
            return

        header = {
            "from": claim_from or self.username,   # claim_from is only for the /spoof demo
            "to": to,
            "msg_num": self.next_msg_num,
            "timestamp": int(time.time()),
        }
        if claim_from:
            # big number so the spoof gets past the replay check and hits the signature check
            header["msg_num"] = int(time.time())
        packet = cu.encrypt_and_sign(text, self.private_key, recipient_key, header)
        self.send_json(packet)

        self.next_msg_num += 1
        with open(self.counter_file, "w") as f:
            f.write(str(self.next_msg_num))
        self.show(f"(sent #{header['msg_num']} to {to}, encrypted + signed)")

    # ============================================================
    # PART 5: Receiving thread
    # ------------------------------------------------------------
    # This thread only reads from the socket and sorts messages.
    # Chat packets go to a second thread (PART 6) because checking
    # them may need a key lookup, which needs this thread free.
    # ============================================================

    def receive_loop(self):
        try:
            for line in self.reader:
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                mtype = msg.get("type")

                if mtype == "chat":
                    self.inbox.put(msg)
                elif mtype == "key_response":
                    with self.key_cond:
                        self.key_replies[msg["username"]] = msg["public_key"]
                        self.key_cond.notify_all()
                elif mtype == "user_list":
                    self.show(f"Online: {', '.join(msg['users'])}")
                elif mtype == "error":
                    if "username" in msg:  # failed key lookup
                        with self.key_cond:
                            self.key_replies[msg["username"]] = None
                            self.key_cond.notify_all()
                    self.show(f"[server] {msg.get('message')}")
        except OSError:
            pass
        if self.running:
            self.show("Disconnected from server.")
            self.running = False
            os._exit(0)

    # ============================================================
    # PART 6: Replay protection + verify/decrypt incoming
    # ------------------------------------------------------------
    # Order (from the spec):
    #   1. message number must be higher than the last one we
    #      accepted from this sender (stops replays)
    #   2. verify the signature with the sender's public key
    #   3. unwrap the AES key with our private key
    #   4. decrypt, then display
    # If anything fails we show NOTHING from the message, just why.
    # ============================================================

    def process_loop(self):
        while True:
            pkt = self.inbox.get()
            sender = str(pkt.get("from"))
            num = pkt.get("msg_num")

            # step 1: replay check
            if not isinstance(num, int):
                self.reject(sender, num, "message number is missing or not a number")
                continue
            last = self.highest_seen.get(sender, 0)
            if num <= last:
                self.reject(sender, num, f"REPLAY - message #{num} already seen "
                                         f"(last accepted from {sender} was #{last})")
                continue

            sender_key = self.get_public_key(sender)
            if sender_key is None:
                self.reject(sender, num, f"no public key for '{sender}', can't verify")
                continue

            # steps 2-4 live in crypto_utils.decrypt_and_verify
            try:
                text = cu.decrypt_and_verify(pkt, self.private_key, sender_key)
            except cu.SecurityError as e:
                self.reject(sender, num, str(e))
                continue

            if pkt.get("to") != self.username:
                self.reject(sender, num, f"addressed to '{pkt.get('to')}', not to us")
                continue

            # passed everything: remember the number, then show it
            self.highest_seen[sender] = num
            with open(self.seen_file, "w") as f:
                json.dump(self.highest_seen, f)
            when = time.strftime("%H:%M:%S", time.localtime(pkt.get("timestamp", 0)))
            self.show(f"[{when}] {sender} (#{num}, signature VALID): {text}")

    def reject(self, sender, num, reason):
        self.show(f"[REJECTED] message #{num} from '{sender}': {reason}")

    # ============================================================
    # PART 7: Command loop
    # ============================================================

    def show(self, text):
        print(f"\r{text}\n> ", end="", flush=True)

    def run(self):
        threading.Thread(target=self.receive_loop, daemon=True).start()
        threading.Thread(target=self.process_loop, daemon=True).start()

        print(HELP)
        current = None   # who plain text goes to
        while True:
            try:
                line = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue

            if line.startswith("/msg "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("usage: /msg <user> <text>")
                    continue
                self.send_chat(parts[1], parts[2])
            elif line.startswith("/to "):
                current = line.split()[1]
                print(f"Now talking to {current}. Just type to send.")
            elif line == "/users":
                self.send_json({"type": "list_users"})
            elif line.startswith("/spoof "):
                # dishonest-user demo: sign with OUR key but claim to be someone else
                parts = line.split(" ", 3)
                if len(parts) < 4:
                    print("usage: /spoof <to> <pretend_to_be> <text>")
                    continue
                self.send_chat(parts[1], parts[3], claim_from=parts[2])
            elif line in ("/help", "/?"):
                print(HELP)
            elif line == "/quit":
                break
            elif line.startswith("/"):
                print("Unknown command. Type /help")
            elif current:
                self.send_chat(current, line)
            else:
                print("Pick someone first: /to <user>  or  /msg <user> <text>")

        self.running = False
        self.sock.close()
        print("Bye.")


HELP = """Commands:
  /msg <user> <text>          send one message
  /to <user>                  set who plain text goes to
  /users                      list who's online
  /spoof <to> <as> <text>     (attack demo) pretend to be another user
  /quit                       leave"""


def main():
    parser = argparse.ArgumentParser(description="Secure chat client")
    parser.add_argument("username")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    client = ChatClient(args.username, args.host, args.port)
    client.load_or_create_keys()
    client.connect_and_register()
    client.run()


if __name__ == "__main__":
    main()
