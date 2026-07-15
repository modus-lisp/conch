;;;; sftp-test.lisp — SFTP put/get/ls/mkdir/realpath over real OpenSSH.  Run from conch/.
(require :asdf)
(require :sb-bsd-sockets)
(push #p"/home/claude/natrium/" asdf:*central-registry*)
(asdf:load-system :natrium)
(dolist (f '("packages" "conditions" "buffer" "transport" "cipher" "kex"
             "auth" "channel" "scp" "sftp" "client"))
  (load (format nil "src/~a.lisp" f)))
(in-package :conch)

(handler-case
    (with-sftp (s "127.0.0.1" :port 2222 :user "claude"
                  :identity "/tmp/sshtest/client_ed25519")
      (format t "~&SFTP version ~d~%" (sftp-version s))
      (format t "realpath \".\" = ~a~%" (sftp-realpath s "."))
      (format t "put: ~d bytes -> /tmp/sshtest/sftp-up.txt~%"
              (sftp-put s "/tmp/sshtest/upload-src.txt" "/tmp/sshtest/sftp-up.txt"))
      (format t "get: ~d bytes -> /tmp/sshtest/sftp-down.txt~%"
              (sftp-get s "/tmp/sshtest/sftp-up.txt" "/tmp/sshtest/sftp-down.txt"))
      (ignore-errors (sftp-rmdir s "/tmp/sshtest/sftp-dir"))
      (sftp-mkdir s "/tmp/sshtest/sftp-dir")
      (format t "mkdir /tmp/sshtest/sftp-dir ok~%")
      (format t "ls /tmp/sshtest = ~{~a ~}~%"
              (sort (remove-if (lambda (n) (member n '("." "..") :test #'string=))
                               (sftp-ls s "/tmp/sshtest"))
                    #'string<))
      (format t "*** sftp ops complete ***~%"))
  (error (e) (format t "~%SFTP-ERROR: ~a~%" e)))
(finish-output)
