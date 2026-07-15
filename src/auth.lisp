;;;; auth.lisp — the authentication layer (RFC 4252): publickey with Ed25519.

(in-package #:conch)

(defconstant +msg-userauth-request+ 50)
(defconstant +msg-userauth-failure+ 51)
(defconstant +msg-userauth-success+ 52)
(defconstant +msg-userauth-banner+ 53)

(defun ssh-ed25519-blob (payload)
  "An ssh-ed25519 key/signature blob: string \"ssh-ed25519\" ‖ string PAYLOAD."
  (let ((w (make-writer)))
    (w-string w "ssh-ed25519")
    (w-string w payload)
    (writer-bytes w)))

(defun request-service (conn name)
  "SERVICE_REQUEST / SERVICE_ACCEPT (the first encrypted exchange)."
  (let ((w (make-writer)))
    (w-byte w +msg-service-request+)
    (w-string w name)
    (write-packet conn (writer-bytes w)))
  (expect-msg conn +msg-service-accept+ "SERVICE_ACCEPT"))

(defun userauth-publickey (conn username secret-key public-key)
  "Authenticate as USERNAME with an Ed25519 key.  SECRET-KEY is the 32-byte seed,
   PUBLIC-KEY the 32-byte public key.  Returns T on success or signals
   SSH-AUTH-ERROR."
  (let* ((pub-blob (ssh-ed25519-blob public-key))
         ;; the blob the client signs (RFC 4252 §7): session-id then the request
         ;; up to and including the public key
         (signed (let ((w (make-writer)))
                   (w-string w (ssh-conn-session-id conn))
                   (w-byte w +msg-userauth-request+)
                   (w-string w username)
                   (w-string w "ssh-connection")
                   (w-string w "publickey")
                   (w-bool w t)
                   (w-string w "ssh-ed25519")
                   (w-string w pub-blob)
                   (writer-bytes w)))
         (sig-blob (ssh-ed25519-blob (n:ed25519-sign secret-key signed)))
         (req (let ((w (make-writer)))
                (w-byte w +msg-userauth-request+)
                (w-string w username)
                (w-string w "ssh-connection")
                (w-string w "publickey")
                (w-bool w t)
                (w-string w "ssh-ed25519")
                (w-string w pub-blob)
                (w-string w sig-blob)
                (writer-bytes w))))
    (write-packet conn req)
    (loop for p = (read-payload conn)
          for msg = (aref p 0)
          do (cond ((= msg +msg-userauth-success+) (return t))
                   ((= msg +msg-userauth-banner+))          ; display-only; ignore
                   ((= msg +msg-userauth-failure+)
                    (let ((r (make-reader p 1)))
                      (error 'ssh-auth-error
                             :message (format nil "publickey auth rejected (server still accepts: ~{~a~^ ~})"
                                              (r-name-list r)))))
                   (t (ssh-protocol-error "unexpected reply ~d during userauth" msg))))))
