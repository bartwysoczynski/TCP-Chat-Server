# TCP-Chat-Server
End-to-end encrypted client-server chat in Python. Messages use AES-256-GCM with RSA-OAEP key wrapping and RSA-PSS signatures over the full header, so the relay server can't read, alter or forge them. Includes replay protection and a malicious-server mode for attack demos.
