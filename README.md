# conch

**A from-scratch SSH-2 client in pure Common Lisp.** Clean-room — no OpenSSH, no
libssh, no FFI to any C library. The only platform dependency is SBCL's own
`sb-bsd-sockets` for the default transport.

A conch is a sea shell — and SSH is the Secure **SH**ell. It's also the shell you
*speak through*: whoever holds the conch has the right to speak and be heard.
`conch` gives you an authenticated channel to a remote host and the right to run
commands on it — a shell you hold up and talk into.

conch implements the SSH transport, authentication and connection layers
(RFC 4251–4254) itself; the cryptography comes from its sibling libraries — the
modern primitives from [`natrium`](https://github.com/modus-lisp/natrium)
(X25519, Ed25519, ChaCha20-Poly1305, SHA-2) and the classical ones from
[`seal`](https://github.com/modus-lisp/seal) (RSA and ECDSA host-key
verification). No OpenSSL, no ironclad — the whole stack, from the curve
arithmetic up through the packet layer, is Common Lisp.

## What it does

```lisp
;; run a command
(conch:run "example.com" "uname -a"
           :user "me" :identity "~/.ssh/id_ed25519")     ; => (values stdout exit-status stderr)

;; copy files (scp) — a directory is copied recursively
(conch:upload   "host" "report.pdf" "/srv/docs/" :user "me" :identity key)
(conch:download "host" "/var/log/app" "./logs"   :user "me" :identity key)   ; recursive

;; SFTP
(conch:with-sftp (s "host" :user "me" :identity key)
  (conch:sftp-put s "local.tar" "/backup/local.tar")
  (conch:sftp-ls  s "/backup"))
```

By default the server is checked against `~/.ssh/known_hosts` (trust-on-first-use,
and a changed key is rejected as a possible man-in-the-middle).

## Conformance

Every layer is validated against a real **OpenSSH 9.2** server:

| layer | conch speaks |
|---|---|
| **Key exchange** | `curve25519-sha256` (X25519), with OpenSSH strict-KEX (the Terrapin countermeasure) |
| **Host keys** | `ssh-ed25519`, `ecdsa-sha2-nistp256/384`, `rsa-sha2-256/512` — signature verified, fingerprint checked against known_hosts |
| **Cipher** | `chacha20-poly1305@openssh.com` (AEAD) |
| **Authentication** | `publickey` with an Ed25519 key (deterministic signing — no RNG in the signing path) |
| **Connection** | session channels: `exec`, and `scp` (files + directory trees) and `sftp` (v3) |

Each host-key type was verified against a server configured with exactly that
key; the computed fingerprint matches `ssh-keygen` in every case.

## Architecture

`src/`: `buffer` (the SSH wire codec — RFC 4251 §5) · `transport` (TCP, version
exchange, the binary packet protocol) · `cipher`
(chacha20-poly1305@openssh.com) · `kex` (curve25519 key exchange, the exchange
hash, host-key signature dispatch) · `host-keys` (known_hosts) · `auth`
(publickey) · `channel` (the bidirectional connection layer) · `scp` · `sftp` ·
`client` (the high-level API + OpenSSH private-key loading).

The ecosystem underneath: **natrium** is the constant-time modern crypto floor;
**seal** (a pure-CL TLS client) contributes RSA/ECDSA verification; conch is the
SSH client that stands on both.

## Not yet

AES-GCM/CTR ciphers (chacha20-poly1305 is negotiated with every modern server),
an interactive shell / PTY, encrypted (passphrase-protected) private keys, and
scp/sftp timestamp preservation. Contributions welcome.

## Running the tests

The `inspect/` scripts exercise each layer against a local `sshd`. See
`inspect/run-test.lisp` (exec), `scp-test.lisp`, `rec-test.lisp` (recursive scp),
`sftp-test.lisp`, and `interop-test.lisp` (RSA/ECDSA host keys).

MIT. Research / educational; **not audited** — do not use it to protect anything
that matters without an independent review.
