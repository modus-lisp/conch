;;;; run-test.lisp — end-to-end exec over SSH.  Run from the conch/ directory
;;;; (relative compile-file avoids stale asdf fasls).
(require :asdf)
(require :sb-bsd-sockets)
(push #p"/home/claude/natrium/" asdf:*central-registry*)
(asdf:load-system :natrium)
(dolist (f '("packages" "conditions" "buffer" "transport" "cipher" "kex"
             "auth" "channel" "client"))
  (load (format nil "src/~a.lisp" f)))          ; load source directly (no fasl)
(in-package :conch)

(handler-case
    (multiple-value-bind (out status err)
        (run "127.0.0.1" "echo 'hello from conch'; id -un; uname -sm; expr 6 '*' 7"
             :port 2222 :user "claude" :identity "/tmp/sshtest/client_ed25519"
             :host-key-verifier
             (lambda (blob pub) (declare (ignore pub))
               (format t "~&[verified host key ~a]~%" (host-key-fingerprint blob))))
      (format t "~%exit-status: ~a~%--- stdout ---~%~a" status out)
      (when (plusp (length err)) (format t "--- stderr ---~%~a" err))
      (format t "~%*** conch ran a command over SSH ***~%"))
  (error (e) (format t "~%CONCH-ERROR: ~a~%" e)))
(finish-output)
