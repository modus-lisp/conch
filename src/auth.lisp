;;;; auth.lisp — the authentication layer (RFC 4252): publickey with Ed25519, password, and
;;;; keyboard-interactive (RFC 4256) answered with the password -- the way most servers that take a
;;;; password take it (OpenSSH's KbdInteractiveAuthentication; macOS's sshd offers only that).

(in-package #:conch)

(defconstant +msg-userauth-request+ 50)
(defconstant +msg-userauth-failure+ 51)
(defconstant +msg-userauth-success+ 52)
(defconstant +msg-userauth-banner+ 53)
(defconstant +msg-userauth-60+ 60)          ; PASSWD_CHANGEREQ (password) / INFO_REQUEST (keyboard-interactive)
(defconstant +msg-userauth-info-response+ 61)

(defun %auth-reply (conn method)
  "Read userauth replies until success (T), failure (signals SSH-AUTH-ERROR naming what the server
   still accepts), or a message 60 (returned as its payload, for the caller)."
  (loop for p = (read-payload conn)
        for msg = (aref p 0)
        do (cond ((= msg +msg-userauth-success+) (return t))
                 ((= msg +msg-userauth-banner+))
                 ((= msg +msg-userauth-failure+)
                  (let ((r (make-reader p 1)))
                    (error 'ssh-auth-error
                           :message (format nil "~a auth rejected (server still accepts: ~{~a~^ ~})"
                                            method (r-name-list r)))))
                 ((= msg +msg-userauth-60+) (return p))
                 (t (ssh-protocol-error "unexpected reply ~d during ~a auth" msg method)))))

(defun userauth-methods (conn username)
  "The methods the server accepts for USERNAME (a \"none\" request): a list of strings, or T when
   it lets USERNAME in with none at all."
  (let ((w (make-writer)))
    (w-byte w +msg-userauth-request+) (w-string w username)
    (w-string w "ssh-connection") (w-string w "none")
    (write-packet conn (writer-bytes w)))
  (loop for p = (read-payload conn)
        for msg = (aref p 0)
        do (cond ((= msg +msg-userauth-success+) (return t))
                 ((= msg +msg-userauth-banner+))
                 ((= msg +msg-userauth-failure+) (return (r-name-list (make-reader p 1))))
                 (t (ssh-protocol-error "unexpected reply ~d to a none request" msg)))))

(defun userauth-password (conn username password)
  "Authenticate as USERNAME with PASSWORD (RFC 4252 §8).  T, or SSH-AUTH-ERROR."
  (let ((w (make-writer)))
    (w-byte w +msg-userauth-request+) (w-string w username)
    (w-string w "ssh-connection") (w-string w "password")
    (w-bool w nil) (w-string w password)
    (write-packet conn (writer-bytes w)))
  (let ((r (%auth-reply conn "password")))
    (if (eq r t)
        t
        (error 'ssh-auth-error :message "the server wants the password changed first"))))

(defun userauth-keyboard-interactive (conn username password)
  "Authenticate as USERNAME by keyboard-interactive (RFC 4256), answering every prompt with
   PASSWORD -- which is what a password prompt over keyboard-interactive is.  T, or SSH-AUTH-ERROR."
  (let ((w (make-writer)))
    (w-byte w +msg-userauth-request+) (w-string w username)
    (w-string w "ssh-connection") (w-string w "keyboard-interactive")
    (w-string w "") (w-string w "")                 ; language, submethods
    (write-packet conn (writer-bytes w)))
  (loop
    (let ((r (%auth-reply conn "keyboard-interactive")))
      (when (eq r t) (return t))
      ;; INFO_REQUEST: name, instruction, language, then the prompts -- answered, all, with PASSWORD
      ;; (zero prompts, a server's "anything else?", gets zero answers)
      (let* ((rd (make-reader r 1)))
        (r-string rd) (r-string rd) (r-string rd)
        (let ((n (r-u32 rd)) (w (make-writer)))
          (dotimes (i n) (r-string rd) (r-bool rd))
          (w-byte w +msg-userauth-info-response+)
          (w-u32 w n)
          (dotimes (i n) (w-string w password))
          (write-packet conn (writer-bytes w)))))))

(defun userauth-with-password (conn username password &optional methods)
  "PASSWORD by whichever way the server takes one: password, else keyboard-interactive.  METHODS,
   the server's list when the caller has it (a failed publickey says it), saves the none request."
  (let ((m (or methods (userauth-methods conn username))))
    (cond ((eq m t) t)
          ((member "password" m :test #'string=) (userauth-password conn username password))
          ((member "keyboard-interactive" m :test #'string=)
           (userauth-keyboard-interactive conn username password))
          (t (error 'ssh-auth-error
                    :message (format nil "the server takes no password (it accepts: ~{~a~^ ~})" m))))))

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
