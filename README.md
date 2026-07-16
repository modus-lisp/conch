# conch

**A from-scratch SSH-2 client and server in pure Common Lisp.** Clean-room — no
OpenSSH, no libssh, no FFI to any C library. The only platform dependency is
SBCL's own `sb-bsd-sockets` for the default transport.

A conch is a sea shell — and SSH is the Secure **SH**ell. It's also the shell you
*speak through*: whoever holds the conch has the right to speak and be heard.
`conch` gives you an authenticated channel — either end of it: connect to a
remote host and run commands on it, or *be* the host and answer.  A shell you
hold up, and one you speak into.

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

;; be the server, too — Ed25519 host key, publickey auth, exec sessions
(conch:serve 2222
  :host-key "host_ed25519"                        ; the server's Ed25519 host key
  :authorized-keys (list client-pubkey-32bytes)   ; NIL = any key with a valid signature
  :exec (lambda (command)                         ; command string, or NIL for a shell
          (values (format nil "you ran: ~a~%" command) 0)))  ; => (values output exit-code)
;; then:  ssh -p 2222 -i client_ed25519 user@host 'echo hi'
```

By default the client checks the server against `~/.ssh/known_hosts`
(trust-on-first-use, and a changed key is rejected as a possible
man-in-the-middle).

## Conformance

The **client** is validated against a real **OpenSSH 9.2** server, and the
**server** against the real **OpenSSH client** — the protocol works in both
directions:

| layer | conch speaks |
|---|---|
| **Key exchange** | `curve25519-sha256` (X25519), with OpenSSH strict-KEX (the Terrapin countermeasure) |
| **Host keys** | client verifies `ssh-ed25519`, `ecdsa-sha2-nistp256/384`, `rsa-sha2-256/512`; the server signs with `ssh-ed25519` |
| **Cipher** | `chacha20-poly1305@openssh.com` (AEAD) |
| **Authentication** | `publickey` with an Ed25519 key — the client signs, the server verifies and checks it against its authorized keys |
| **Connection** | session channels: `exec` (both roles) plus `scp` (files + directory trees) and `sftp` (v3) on the client |

Each host-key type was verified against a server configured with exactly that
key; the fingerprint matches `ssh-keygen` in every case. The server side was
driven by `ssh` itself: it completes KEX, authenticates by publickey, rejects an
unauthorized key with *Permission denied (publickey)*, runs the command, and
returns the right exit status.

## Architecture

`src/`: `buffer` (the SSH wire codec — RFC 4251 §5) · `transport` (TCP, version
exchange, the binary packet protocol) · `cipher`
(chacha20-poly1305@openssh.com) · `kex` (curve25519 key exchange, the exchange
hash, host-key signature dispatch) · `host-keys` (known_hosts) · `auth`
(publickey) · `channel` (the bidirectional connection layer) · `scp` · `sftp` ·
`client` (the high-level API + OpenSSH private-key loading) · `server` (the
mirror role: listen/accept, server-side KEX signing the exchange hash with the
host key, publickey auth verification, and `exec` sessions).

The ecosystem underneath: **natrium** is the constant-time modern crypto floor;
**seal** (a pure-CL TLS client) contributes RSA/ECDSA verification; conch is the
SSH client and server that stands on both.

## Not yet

AES-GCM/CTR ciphers (chacha20-poly1305 is negotiated with every modern peer), an
interactive shell / PTY, encrypted (passphrase-protected) private keys, and
scp/sftp timestamp preservation. The server does `exec` sessions with publickey
auth; port-forwarding, SFTP-as-a-server, and password auth are future work.
Contributions welcome.

## Running the tests

The `inspect/` scripts exercise each layer against a local `sshd` (client) or the
`ssh` client (server). See `inspect/run-test.lisp` (exec), `scp-test.lisp`,
`rec-test.lisp` (recursive scp), `sftp-test.lisp`, `interop-test.lisp` (RSA/ECDSA
host keys), and `server-test.lisp` (conch's server via conch's client, one
process).

MIT. Research / educational; **not audited** — do not use it to protect anything
that matters without an independent review.
