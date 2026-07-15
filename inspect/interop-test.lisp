(require :asdf)
(require :sb-bsd-sockets)
(push #p"/home/claude/natrium/" asdf:*central-registry*)
(asdf:load-system :natrium)
(asdf:load-system :seal)
(dolist (f '("packages" "conditions" "buffer" "transport" "cipher" "kex"
             "host-keys" "auth" "channel" "scp" "sftp" "client"))
  (load (format nil "src/~a.lisp" f)))
(in-package :conch)
(handler-case
    (multiple-value-bind (out st)
        (run "127.0.0.1" "echo interop-ok"
             :port 2222 :user "claude" :identity "/tmp/sshtest/client_ed25519"
             :host-key-verifier
             (lambda (k-s)
               (format t "~&host-key type: ~a~%" (r-cstring (make-reader k-s)))
               (format t "fingerprint:   ~a~%" (host-key-fingerprint k-s))
               t))
      (format t "exec result: ~a (exit ~a)~%" (string-trim '(#\Newline) out) st)
      (format t "*** interop OK ***~%"))
  (error (e) (format t "~%INTEROP-ERROR: ~a~%" e)))
(finish-output)
