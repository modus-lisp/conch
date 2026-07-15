;;;; packages.lisp — conch

(defpackage #:conch
  (:use #:cl)
  (:local-nicknames (#:n #:natrium))
  (:documentation
   "conch — a from-scratch SSH-2 client in pure Common Lisp.  A conch is a shell,
    and the one who holds it may speak: conch gives you an authenticated channel
    to a remote host and the right to run commands on it.  Clean-room — the SSH
    transport, auth and connection layers implemented from RFC 4251-4254; the
    cryptography comes from the sibling `natrium` library (X25519, Ed25519,
    ChaCha20-Poly1305, SHA-2, HMAC).  No OpenSSH, no libssh, no FFI; the only
    platform dependency is SBCL's own sb-bsd-sockets for the default transport.")
  (:export
   ;; connection
   #:connect #:disconnect #:with-connection
   ;; running commands
   #:run #:exec
   ;; raw channel (for streaming protocols like git-over-SSH)
   #:open-session #:chan-exec #:chan-subsystem #:chan-close #:chan-send-eof
   #:chan-write #:chan-read-exact #:chan-read-byte #:chan-read-line #:chan-read-all
   #:chan-avail #:chan-eof
   ;; file transfer (scp)
   #:upload #:download #:scp-upload #:scp-download
   ;; sftp
   #:with-sftp #:sftp-open-session
   #:sftp-get #:sftp-put #:sftp-ls #:sftp-realpath
   #:sftp-mkdir #:sftp-rmdir #:sftp-remove
   #:sftp-download #:sftp-upload #:sftp-list
   ;; keys / host verification
   #:load-private-key #:host-key-fingerprint #:make-known-hosts-verifier
   ;; conditions
   #:ssh-error #:ssh-protocol-error #:ssh-host-key-error #:ssh-auth-error))
