;;;; conch.asd — a from-scratch SSH-2 client in pure Common Lisp.

(asdf:defsystem :conch
  :description "A clean-room SSH-2 client in pure Common Lisp: the transport,
authentication and connection layers (RFC 4251-4254) with curve25519-sha256 key
exchange, ssh-ed25519 host keys, chacha20-poly1305@openssh.com, and publickey
auth. Cryptography from the sibling `natrium` library. No OpenSSH, no libssh, no
FFI; the only platform dependency is SBCL's sb-bsd-sockets."
  :version "0.0.1"
  :author "ynniv"
  :license "MIT"
  :depends-on ("natrium" "sb-bsd-sockets")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "packages")
     (:file "conditions")
     (:file "buffer")
     (:file "transport")
     (:file "cipher")
     (:file "kex")
     (:file "auth")
     (:file "channel")
     (:file "scp")
     (:file "sftp")
     (:file "client")))))
