(require :asdf)
(require :sb-bsd-sockets)
(push #p"/home/claude/natrium/" asdf:*central-registry*)
(asdf:load-system :natrium)
(dolist (f '("packages" "conditions" "buffer" "transport" "cipher" "kex"
             "auth" "channel" "scp" "sftp" "client"))
  (load (format nil "src/~a.lisp" f)))
(in-package :conch)
(handler-case
    (let ((args '(:port 2222 :user "claude" :identity "/tmp/sshtest/client_ed25519")))
      (format t "~&upload tree: ~d file-bytes~%"
              (apply #'upload "127.0.0.1" "/tmp/sshtest/tree" "/tmp/sshtest/uptree" args))
      (format t "download tree: ~d file-bytes~%"
              (apply #'download "127.0.0.1" "/tmp/sshtest/uptree" "/tmp/sshtest/downtree" args))
      (format t "*** recursive scp done ***~%"))
  (error (e) (format t "~%REC-ERROR: ~a~%" e)))
(finish-output)
