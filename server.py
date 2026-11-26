"""
server.py - relay server for the secure chat.

The server is a directory (username -> public key) and a relay.
It only reads "type", "from" and "to". Everything else in a chat
message is opaque base64 that it passes along untouched.

  PART 1  Setup + shared state
  PART 2  Sending helpers + logging
  PART 3  Message handlers (register, key request, user list, chat)
  PART 4  Per-client thread
  PART 5  Malicious mode (attack demos)
  PART 6  Main: listen for connections

Run:
  python server.py                    normal server
  python server.py --malicious        attack-demo server
"""

import argparse
import copy
import base64
import json
import re
import socket
import threading
import time


# ============================================================
# PART 1: Setup + shared state
# ============================================================

HOST = "127.0.0.1"
PORT = 5000
LOG_FILE = "server_log.txt"

# username -> {"public_key": PEM string, "sock": socket}
directory = {}
dir_lock = threading.Lock()

# one lock per socket so two threads never interleave writes
send_locks = {}

USERNAME_OK = re.compile(r"^[A-Za-z0-9_-]{1,32}$")   # no "|" so it can't break the signed header


# ============================================================
# PART 2: Sending helpers + logging
# ============================================================

def send_json(sock, obj):
    """Messages are one JSON object per line."""
    data = (json.dumps(obj) + "\n").encode("utf-8")
    lock = send_locks.setdefault(sock, threading.Lock())
    with lock:
        sock.sendall(data)


def broadcast_user_list():
    with dir_lock:
        users = sorted(directory.keys())
        socks = [info["sock"] for info in directory.values()]
    for s in socks:
        try:
            send_json(s, {"type": "user_list", "users": users})
        except OSError:
            pass


def log_relay(packet, note=""):
    """Log every relayed message so we can show the server only sees ciphertext."""
    stamp = time.strftime("%H:%M:%S")
    short = lambda s: s if len(s) <= 40 else s[:40] + "..."
    line = (f"[{stamp}] RELAY {packet.get('from')} -> {packet.get('to')} "
            f"#{packet.get('msg_num')} | encrypted_key={short(packet.get('encrypted_key', ''))} "
            f"| nonce={packet.get('nonce')} | ciphertext={short(packet.get('ciphertext', ''))}")
    if note:
        line += f"  <<< {note}"
    print(line)
    # full packet goes to the log file
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps({"time": stamp, "note": note, "packet": packet}) + "\n")


# ============================================================
# PART 3: Message handlers
# ============================================================

def handle_register(sock, msg):
    name = msg.get("username", "")
    pem = msg.get("public_key", "")

    if not USERNAME_OK.match(name):
        return send_json(sock, {"type": "error", "message": "bad username (letters, numbers, _ or - only)"})
    # safety net: never accept anything that looks like a private key
    if "PRIVATE" in pem or not pem.startswith("-----BEGIN PUBLIC KEY-----"):
        return send_json(sock, {"type": "error", "message": "only a PEM public key is accepted"})

    with dir_lock:
        if name in directory:
            return send_json(sock, {"type": "error", "message": f"'{name}' is already online"})
        directory[name] = {"public_key": pem, "sock": sock}

    print(f"[+] {name} registered")
    send_json(sock, {"type": "register_ok", "username": name})
    broadcast_user_list()
    return name


def handle_key_request(sock, msg):
    target = msg.get("username", "")
    with dir_lock:
        info = directory.get(target)
    if info:
        send_json(sock, {"type": "key_response", "username": target, "public_key": info["public_key"]})
    else:
        send_json(sock, {"type": "error", "message": f"unknown user '{target}'", "username": target})


def handle_user_list(sock):
    with dir_lock:
        users = sorted(directory.keys())
    send_json(sock, {"type": "user_list", "users": users})


def handle_chat(sock, me, msg):
    # Only the routing fields are read. The rest is never opened.
    if msg.get("from") != me:
        # we don't trust it, but the receiver's signature check is what actually protects them
        print(f"[!] {me} sent a message claiming to be from '{msg.get('from')}'")

    if MALICIOUS:
        msg, deliver_to = attacker.tamper(msg)
    else:
        deliver_to = msg.get("to")

    relay(sock, msg, deliver_to)


def relay(sender_sock, msg, deliver_to, note=""):
    with dir_lock:
        info = directory.get(deliver_to)
    if not info:
        send_json(sender_sock, {"type": "error", "message": f"'{deliver_to}' is not online"})
        return
    if MALICIOUS and not note:
        note = attacker.last_note
    log_relay(msg, note)
    send_json(info["sock"], msg)
    if MALICIOUS and not attacker.last_note:
        attacker.remember(msg, deliver_to)   # only keep clean, valid messages for replay


# ============================================================
# PART 4: Per-client thread
# ============================================================

def client_thread(sock, addr):
    me = None
    try:
        f = sock.makefile("r", encoding="utf-8")
        for line in f:
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                send_json(sock, {"type": "error", "message": "bad JSON"})
                continue

            mtype = msg.get("type")
            if me is None:
                # must register before anything else
                if mtype == "register":
                    me = handle_register(sock, msg)
                else:
                    send_json(sock, {"type": "error", "message": "register first"})
            elif mtype == "key_request":
                handle_key_request(sock, msg)
            elif mtype == "list_users":
                handle_user_list(sock)
            elif mtype == "chat":
                handle_chat(sock, me, msg)
            else:
                send_json(sock, {"type": "error", "message": f"unknown type '{mtype}'"})
    except (OSError, UnicodeDecodeError):
        pass
    finally:
        if me:
            with dir_lock:
                directory.pop(me, None)
            print(f"[-] {me} left")
            broadcast_user_list()
        send_locks.pop(sock, None)
        sock.close()


# ============================================================
# PART 5: Malicious mode
# ------------------------------------------------------------
# Type a command in the server window to arm an attack. It is
# applied to the NEXT chat message the server relays.
#   flip              flip one byte of the ciphertext
#   recipient <user>  rewrite the "to" field and deliver there
#   msgnum            bump the message number in the header
#   redirect <user>   deliver to another user, header untouched
#   replay            resend the last relayed message right now
#   off               disarm
# ============================================================

class Attacker:
    def __init__(self):
        self.armed = None        # (attack, arg)
        self.last_note = ""
        self.last_msg = None     # for replay
        self.last_to = None

    def tamper(self, msg):
        deliver_to = msg.get("to")
        self.last_note = ""
        if not self.armed:
            return msg, deliver_to

        attack, arg = self.armed
        self.armed = None
        msg = copy.deepcopy(msg)

        if attack == "flip":
            raw = bytearray(base64.b64decode(msg["ciphertext"]))
            raw[0] ^= 0x01
            msg["ciphertext"] = base64.b64encode(bytes(raw)).decode()
            self.last_note = "ATTACK: flipped 1 byte of ciphertext"
        elif attack == "recipient":
            msg["to"] = arg
            deliver_to = arg
            self.last_note = f"ATTACK: changed 'to' header to {arg}"
        elif attack == "msgnum":
            msg["msg_num"] = int(msg["msg_num"]) + 1000
            self.last_note = "ATTACK: changed msg_num in header"
        elif attack == "redirect":
            deliver_to = arg
            self.last_note = f"ATTACK: delivering message meant for {msg['to']} to {arg}"
        return msg, deliver_to

    def remember(self, msg, deliver_to):
        self.last_msg, self.last_to = msg, deliver_to

    def replay(self):
        if not self.last_msg:
            print("[attack] nothing to replay yet")
            return
        with dir_lock:
            info = directory.get(self.last_to)
        if not info:
            print(f"[attack] {self.last_to} is offline")
            return
        log_relay(self.last_msg, "ATTACK: replaying an old valid message")
        send_json(info["sock"], self.last_msg)


def attack_console():
    print("MALICIOUS MODE. Commands: flip | recipient <user> | msgnum | "
          "redirect <user> | replay | off")
    while True:
        try:
            parts = input().strip().split()
        except EOFError:
            return
        if not parts:
            continue
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else None

        if cmd in ("flip", "msgnum"):
            attacker.armed = (cmd, None)
            print(f"[attack] '{cmd}' armed for the next message")
        elif cmd in ("recipient", "redirect"):
            if not arg:
                print(f"[attack] usage: {cmd} <user>")
                continue
            attacker.armed = (cmd, arg)
            print(f"[attack] '{cmd} {arg}' armed for the next message")
        elif cmd == "replay":
            attacker.replay()
        elif cmd == "off":
            attacker.armed = None
            print("[attack] disarmed")
        else:
            print("[attack] unknown command")


# ============================================================
# PART 6: Main
# ============================================================

MALICIOUS = False
attacker = Attacker()


def main():
    global MALICIOUS
    parser = argparse.ArgumentParser(description="Secure chat relay server")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--malicious", action="store_true", help="enable attack demo mode")
    args = parser.parse_args()
    MALICIOUS = args.malicious

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen()
    print(f"Server listening on {args.host}:{args.port}  (log: {LOG_FILE})")

    if MALICIOUS:
        threading.Thread(target=attack_console, daemon=True).start()

    try:
        while True:
            sock, addr = srv.accept()
            threading.Thread(target=client_thread, args=(sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
