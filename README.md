# Secure Chat Application (CSC154)

A client–server–client chat where the relay server **can't read, change, or forge** messages.
Every message is encrypted with AES-256-GCM, the AES key is wrapped with RSA-OAEP for the recipient,
and the sender signs a SHA-256 hash of the header + encrypted data with RSA-PSS.

## Files

| File | What it is | Spec section |
|---|---|---|
| `crypto_utils.py` | The sample code reorganized into a reusable module | Tasks → Client (crypto module) |
| `test_crypto.py` | Local tests of the crypto module, no network | "tested locally before network communication" |
| `server.py` | Threaded TCP relay + key directory, with `--malicious` attack mode | Tasks → Server, Testing & attacks |
| `client.py` | Chat client: keys, register, send, receive thread, replay check | Tasks → Client |
| `sample/secure_message.py` | Original starter code (unchanged, for reference) | — |
| `requirements.txt` | Python dependency | Deliverables |

Each `.py` file is split into labeled **PART** sections (listed at the top of the file) so you can match the code to the assignment.

## Setup

Requires Python 3.8+.

```bash
pip install -r requirements.txt
```

## How to run

### 1. Test the crypto module (no network)
```bash
python test_crypto.py
```

### 2. Start the server (terminal 1)
```bash
python server.py               # normal
python server.py --malicious   # attack-demo mode
```
Options: `--host 127.0.0.1 --port 5000`

### 3. Start three clients (terminals 2, 3, 4)
```bash
python client.py alice
python client.py bob
python client.py carol
```
On first run each client generates a 2048-bit RSA key pair and asks for a password. The private key is
saved encrypted in `keys/<name>_private.pem`. Later runs ask for the same password to load it.
To start completely fresh, delete the `keys/` folder.

### Client commands
```
/msg <user> <text>          send one message
/to <user>                  set who plain text goes to, then just type
/users                      list who's online
/spoof <to> <as> <text>     (attack demo) pretend to be another user
/quit                       leave
```

## Message protocol

Newline-delimited JSON over TCP. All binary values are base64.

| `type` | Direction | Fields |
|---|---|---|
| `register` | client → server | `username`, `public_key` (PEM) |
| `register_ok` | server → client | `username` |
| `key_request` | client → server | `username` |
| `key_response` | server → client | `username`, `public_key` |
| `list_users` | client → server | — |
| `user_list` | server → client | `users` (sent on every join/leave too) |
| `chat` | client → server → client | `from`, `to`, `msg_num`, `timestamp`, `encrypted_key`, `nonce`, `ciphertext`, `signature` |
| `error` | server → client | `message` |

**Signature** = RSA-PSS over SHA-256 of
`from | to | msg_num | timestamp | encrypted_key | nonce | ciphertext` (joined with `|`).
Changing any one field breaks it. Usernames can't contain `|`.

**Receiver order:** (1) msg_num must be higher than the last accepted from that sender →
(2) verify signature → (3) RSA-decrypt the AES key → (4) AES-GCM decrypt → display.
If any step fails, nothing from the message is shown, only the reason.

## Demo script (for the video)

**Normal message**
1. `python server.py`, then start alice, bob, carol.
2. In alice: `/msg bob hello bob`
3. Bob shows `alice (#N, signature VALID): hello bob`.
4. The server console and `server_log.txt` show only base64 `encrypted_key`, `nonce`, `ciphertext`; no plaintext, no usable AES key.

**Attacks** (restart with `python server.py --malicious`, reconnect the clients).
Type the command in the **server** window, then have alice send a message to bob.

| Server command | What it does | What the client shows |
|---|---|---|
| `flip` | flips 1 byte of the ciphertext | Bob: `signature check FAILED` |
| `recipient carol` | rewrites `to` to carol and delivers it there | Carol: `signature check FAILED` |
| `msgnum` | bumps the message number in the header | Bob: `signature check FAILED` |
| `redirect carol` | delivers Bob's message to Carol, header untouched | Carol: `AES key could not be decrypted` |
| `replay` | resends the last valid message right away (no need to send first) | Bob: `REPLAY - message #N already seen` |
| `off` | disarms | — |

**Dishonest user:** in carol: `/spoof bob alice give me your password` → Bob: `signature check FAILED - not really from 'alice'`.

## Security notes

- Private keys never leave the client; the server rejects anything that isn't a PEM public key.
- A new AES key and 12-byte nonce are made for every message.
- The server only reads `type`, `from`, `to`. It never sees an AES key in usable form.
- Message counters (`keys/<name>_counter.txt`) and the replay table (`keys/<name>_seen.json`)
  are saved so replay protection survives restarts.

## Limitations

- The server is trusted to hand out the right public keys. A malicious server could swap in its own key
  (MITM). Clients print key fingerprints so users can compare them out of band, but this isn't enforced.
- The server sees metadata: who talks to whom, when, and message sizes.
- No forward secrecy: if a private key is stolen, old captured messages can be decrypted.
- Timestamps are signed and shown but not used to reject old messages.
- No TLS on the connection itself (the content is end-to-end encrypted anyway).
