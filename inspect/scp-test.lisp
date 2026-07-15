;;;; scp-test.lisp — upload a file via scp, download it back, over real OpenSSH.
;;;; Run from the conch/ directory.
(require :asdf)
(require :sb-bsd-sockets)
(push #p"/home/claude/natrium/" asdf:*central-registry*)
(asdf:load-system :natrium)
(dolist (f '("packages" "conditions" "buffer" "transport" "cipher" "kex"
             "auth" "channel" "scp" "client"))
  (load (format nil "src/~a.lisp" f)))
(in-package :conch)

(handler-case
    (let ((args '(:port 2222 :user "claude" :identity "/tmp/sshtest/client_ed25519")))
      (let ((n (apply #'upload "127.0.0.1" "/tmp/sshtest/upload-src.txt"
                      "/tmp/sshtest/conch-uploaded.txt" args)))
        (format t "~&uploaded ~d bytes -> /tmp/sshtest/conch-uploaded.txt~%" n))
      (multiple-value-bind (n name)
          (apply #'download "127.0.0.1" "/tmp/sshtest/conch-uploaded.txt"
                 "/tmp/sshtest/downloaded.txt" args)
        (format t "downloaded ~d bytes (remote name ~a) -> /tmp/sshtest/downloaded.txt~%" n name))
      (format t "*** scp roundtrip complete ***~%"))
  (error (e) (format t "~%SCP-ERROR: ~a~%" e)))
(finish-output)
