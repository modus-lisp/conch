;;;; kex-probe.lisp — full curve25519-sha256 KEX + encrypted transport against
;;;; a real OpenSSH server: verify the host key, then exchange an ENCRYPTED
;;;; SERVICE_REQUEST/SERVICE_ACCEPT to prove the chacha20-poly1305@openssh.com
;;;; cipher works end to end.
(require :asdf)
;; Sibling repos, found relative to this file so the workspace can live anywhere.
(asdf:initialize-source-registry
 (let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
   `(:source-registry (:tree ,(merge-pathnames "../../" here)) :inherit-configuration)))
(asdf:load-system :conch)
(in-package :conch)

(multiple-value-bind (sock stream) (tcp-connect "127.0.0.1" 2222)
  (let ((conn (make-ssh-conn :socket sock :stream stream)))
    (format t "~&server: ~a~%" (exchange-versions conn))
    (let ((h (do-kex conn
                     :host-key-verifier
                     (lambda (blob pub)
                       (declare (ignore pub))
                       (format t "host key verified: ~a~%" (host-key-fingerprint blob))))))
      (format t "KEX complete — exchange hash H = ~d bytes; session established.~%"
              (length h))
      (format t "strict-kex seq reset: send=~d recv=~d (both 0 => reset applied)~%"
              (ssh-conn-send-seq conn) (ssh-conn-recv-seq conn))
      ;; first ENCRYPTED packet: request the userauth service
      (let ((w (make-writer)))
        (w-byte w +msg-service-request+)
        (w-string w "ssh-userauth")
        (write-packet conn (writer-bytes w)))
      (let* ((p (expect-msg conn +msg-service-accept+ "SERVICE_ACCEPT"))
             (r (make-reader p 1)))
        (format t "~%ENCRYPTED TRANSPORT OK — server accepted service: ~a~%"
                (r-cstring r))))
    (ignore-errors (sb-bsd-sockets:socket-close sock))))
