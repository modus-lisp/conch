;;;; server-test.lisp — conch's SSH server, exercised by conch's own client.
;;;;
;;;;   sbcl --non-interactive --load inspect/server-test.lisp
;;;;
;;;; Runs conch:serve in a thread and connects to it with conch:run in the same
;;;; process — a self-contained round trip of KEX + Ed25519 host key + publickey
;;;; auth + exec.  (The server also interoperates with real OpenSSH: run it with
;;;;   (conch:serve 2222 :host-key "host_ed25519" :exec (lambda (c) ...))
;;;; and connect with  ssh -p 2222 -i client_ed25519 user@127.0.0.1 'echo hi'.)

(require :asdf)
(require :sb-posix)
(handler-bind ((warning #'muffle-warning))
  (let ((*standard-output* (make-broadcast-stream))) (asdf:load-system :conch)))

(defvar *dir* "/tmp/conch-servertest")
(defvar *port* 2225)

(uiop:run-program (list "rm" "-rf" *dir*))
(ensure-directories-exist (format nil "~a/" *dir*))
(uiop:run-program (list "ssh-keygen" "-t" "ed25519" "-f" (format nil "~a/host" *dir*) "-N" "" "-q"))
(uiop:run-program (list "ssh-keygen" "-t" "ed25519" "-f" (format nil "~a/client" *dir*) "-N" "" "-q"))

;; authorize only the client key
(multiple-value-bind (sec pub) (conch::load-private-key (format nil "~a/client" *dir*))
  (declare (ignore sec))
  (let ((ready (sb-thread:make-semaphore)))
    ;; server thread: signal readiness once listening, then serve one connection
    (sb-thread:make-thread
     (lambda ()
       (handler-case
           (let ((conch::*server-id* conch::*server-id*))
             ;; a tiny shim so we can post the semaphore right before accept
             (multiple-value-bind (hs hp) (conch::load-private-key (format nil "~a/host" *dir*))
               (let ((listen (conch::tcp-listen *port*)))
                 (sb-thread:signal-semaphore ready)
                 (unwind-protect
                      (conch::serve-connection (conch::accept-conn listen) hs hp
                                               :authorized-keys (list pub)
                                               :exec (lambda (cmd)
                                                       (values (format nil "conch-server ran: ~a~%" cmd) 0)))
                   (ignore-errors (sb-bsd-sockets:socket-close listen))))))
         (error (e) (format t "~&server thread error: ~a~%" e)))))
    (sb-thread:wait-on-semaphore ready)
    ;; client: connect with conch, accept the host key, run a command
    (multiple-value-bind (out status)
        (conch:run "127.0.0.1" "echo from-conch-client"
                   :port *port* :user "tester"
                   :identity (format nil "~a/client" *dir*)
                   :host-key-verifier (lambda (blob) (declare (ignore blob)) t))
      (format t "~&exec output:  ~a" out)
      (format t "exit status:  ~a~%" status)
      (format t "round trip OK: ~a~%"
              (and (search "conch-server ran: echo from-conch-client" out) (eql status 0))))))
