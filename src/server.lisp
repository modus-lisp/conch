;;;; server.lisp — the SSH-2 *server* side (RFC 4252-4254).
;;;;
;;;; conch is a client; this adds the mirror role, reusing every primitive the
;;;; client already has — the packet layer, the chacha20-poly1305 cipher, the
;;;; curve25519 exchange hash and key derivation, Ed25519 (this time *signing*
;;;; the exchange hash with the host key rather than verifying it).  The server
;;;; flow — version exchange, KEXINIT, ECDH, NEWKEYS, publickey userauth, a
;;;; session channel running an exec handler — is ported from the pre-CL modus
;;;; bare-metal SSH server (net/ssh.lisp), rewritten in conch's idiom.

(in-package #:conch)

(defconstant +msg-userauth-pk-ok+ 60)

(defparameter *server-id* "SSH-2.0-conch_0.1"
  "The server's identification string (without the trailing CR LF).")

(defparameter *server-kex-algs*
  '("curve25519-sha256" "curve25519-sha256@libssh.org" "kex-strict-s-v00@openssh.com"))

;;; ---- listen / accept --------------------------------------------------------

(defun tcp-listen (port &key (backlog 16) (address "0.0.0.0"))
  "A listening TCP socket bound to PORT."
  (let ((sock (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address sock) t)
    (sb-bsd-sockets:socket-bind sock (resolve-address address) port)
    (sb-bsd-sockets:socket-listen sock backlog)
    sock))

(defun accept-conn (listen-sock)
  "Accept one connection and wrap it in an SSH-CONN (pre-handshake)."
  (let ((sock (sb-bsd-sockets:socket-accept listen-sock)))
    (make-ssh-conn :socket sock
                   :stream (sb-bsd-sockets:socket-make-stream
                            sock :input t :output t :element-type '(unsigned-byte 8)
                            :buffering :none))))

(defun server-exchange-versions (conn)
  "Send our identification and read the client's (RFC 4253 §4.2)."
  (setf (ssh-conn-server-id conn) *server-id*)
  (send-raw conn (string->utf8 (format nil "~a~c~c" *server-id* #\Return #\Newline)))
  (loop for line = (read-id-line conn)
        when (and (>= (length line) 4) (string= line "SSH-" :end1 4))
          do (setf (ssh-conn-client-id conn) line)
             (return line)))

;;; ---- key exchange (server role) --------------------------------------------

(defun build-server-kexinit ()
  (let ((w (make-writer)))
    (w-byte w +msg-kexinit+)
    (w-raw w (n:random-bytes 16))
    (w-name-list w *server-kex-algs*)
    (w-name-list w '("ssh-ed25519"))                 ; host-key algorithms we offer
    (w-name-list w *ciphers*) (w-name-list w *ciphers*)
    (w-name-list w *macs*) (w-name-list w *macs*)
    (w-name-list w *compression*) (w-name-list w *compression*)
    (w-name-list w '()) (w-name-list w '())
    (w-bool w nil) (w-u32 w 0)
    (writer-bytes w)))

(defun server-do-kex (conn host-secret host-public)
  "Run one key exchange as the server: agree algorithms, ECDH, sign the exchange
   hash H with the Ed25519 host key, switch on the cipher at NEWKEYS.  Returns H."
  (let ((i-s (build-server-kexinit)))
    (write-packet conn i-s)                            ; KEXINIT first (strict-KEX)
    (let* ((i-c (expect-msg conn +msg-kexinit+ "KEXINIT"))
           (sk (parse-kexinit i-c))
           (strict (and (member "kex-strict-c-v00@openssh.com" (getf sk :kex) :test #'string=) t)))
      (negotiate (getf sk :kex) *server-kex-algs* "kex algorithm")
      (negotiate (getf sk :enc-c2s) *ciphers* "cipher")
      (negotiate (getf sk :enc-s2c) *ciphers* "cipher")
      (negotiate (getf sk :hostkey) '("ssh-ed25519") "host-key algorithm")
      (let* ((init (expect-msg conn +msg-kex-ecdh-init+ "KEX_ECDH_INIT"))
             (q-c (r-string (make-reader init 1))))    ; client ephemeral public
        (multiple-value-bind (priv q-s) (n:x25519-keypair)
          (let* ((k-s (ssh-ed25519-blob host-public)) ; host key blob
                 (k (be->integer (n:x25519 priv q-c)))
                 (h (compute-exchange-hash conn i-c i-s k-s q-c q-s k))
                 (sig (ssh-ed25519-blob (n:ed25519-sign host-secret h))))
            (let ((w (make-writer)))
              (w-byte w +msg-kex-ecdh-reply+)
              (w-string w k-s) (w-string w q-s) (w-string w sig)
              (write-packet conn (writer-bytes w)))
            (unless (ssh-conn-session-id conn) (setf (ssh-conn-session-id conn) h))
            (let* ((sid (ssh-conn-session-id conn))
                   (km (mpint-bytes k))
                   (key-c2s (derive-key km h sid #\C 64))     ; client→server (we receive)
                   (key-s2c (derive-key km h sid #\D 64)))    ; server→client (we send)
              (write-packet conn (make-array 1 :element-type '(unsigned-byte 8)
                                               :initial-element +msg-newkeys+))
              (setf (ssh-conn-send-cipher conn) (make-openssh-cipher key-s2c))
              (when strict (setf (ssh-conn-send-seq conn) 0))
              (expect-msg conn +msg-newkeys+ "NEWKEYS")
              (setf (ssh-conn-recv-cipher conn) (make-openssh-cipher key-c2s))
              (when strict (setf (ssh-conn-recv-seq conn) 0))
              h)))))))

;;; ---- authentication (server role) ------------------------------------------

(defun send-userauth-failure (conn &optional partial)
  (let ((w (make-writer)))
    (w-byte w +msg-userauth-failure+)
    (w-name-list w '("publickey"))
    (w-bool w partial)
    (write-packet conn (writer-bytes w))))

(defun pubkey-authorized-p (pub-blob authorized-keys)
  "Is PUB-BLOB (an ssh-ed25519 key blob) in AUTHORIZED-KEYS?  AUTHORIZED-KEYS may
   be a list of 32-byte public keys or of blobs; NIL means accept any valid key."
  (or (null authorized-keys)
      (let ((pub (parse-ed25519-blob pub-blob "client public key")))
        (some (lambda (k) (equalp pub (if (= (length k) 32) k
                                          (parse-ed25519-blob k "authorized key"))))
              authorized-keys))))

(defun verify-userauth-signature (conn username pub-blob sig-blob)
  "Verify the client's Ed25519 signature over the userauth request (RFC 4252 §7)."
  (let ((signed (let ((w (make-writer)))
                  (w-string w (ssh-conn-session-id conn))
                  (w-byte w +msg-userauth-request+)
                  (w-string w username)
                  (w-string w "ssh-connection")
                  (w-string w "publickey")
                  (w-bool w t)
                  (w-string w "ssh-ed25519")
                  (w-string w pub-blob)
                  (writer-bytes w))))
    (n:ed25519-verify (parse-ed25519-blob pub-blob "client public key") signed
                      (parse-ed25519-blob sig-blob "client signature"))))

(defun server-authenticate (conn &key authorized-keys)
  "Run the server auth loop: SERVICE_REQUEST → publickey userauth.  Returns the
   authenticated (username . public-key-blob), or signals on give-up/close."
  (let ((sr (expect-msg conn +msg-service-request+ "SERVICE_REQUEST")))
    (declare (ignore sr))
    (let ((w (make-writer)))
      (w-byte w +msg-service-accept+) (w-string w "ssh-userauth")
      (write-packet conn (writer-bytes w))))
  (loop
    (let* ((p (expect-msg conn +msg-userauth-request+ "USERAUTH_REQUEST"))
           (r (make-reader p 1))
           (username (r-cstring r))
           (service (r-cstring r))
           (method (r-cstring r)))
      (declare (ignore service))
      (cond
        ((string= method "publickey")
         (let* ((has-sig (r-bool r))
                (alg (r-cstring r))                    ; "ssh-ed25519"
                (pub-blob (r-string r)))
           (declare (ignore alg))
           (cond
             ((not (pubkey-authorized-p pub-blob authorized-keys))
              (send-userauth-failure conn))
             ((not has-sig)                            ; probe: offer to accept this key
              (let ((w (make-writer)))
                (w-byte w +msg-userauth-pk-ok+)
                (w-string w "ssh-ed25519") (w-string w pub-blob)
                (write-packet conn (writer-bytes w))))
             ((verify-userauth-signature conn username pub-blob (r-string r))
              (write-packet conn (make-array 1 :element-type '(unsigned-byte 8)
                                               :initial-element +msg-userauth-success+))
              (return (cons username pub-blob)))
             (t (send-userauth-failure conn)))))
        (t (send-userauth-failure conn))))))            ; "none" and the rest: reject

;;; ---- a session channel running an exec handler -----------------------------

(defun server-write-channel-data (conn chan bytes)
  (let ((w (make-writer)))
    (w-byte w +msg-channel-data+) (w-u32 w chan) (w-string w bytes)
    (write-packet conn (writer-bytes w))))

(defun server-serve-session (conn exec-handler)
  "Accept a session channel and service one exec/shell request by calling
   EXEC-HANDLER with (command-string-or-NIL) → a string (or (values string
   exit-code)).  Streams the result as CHANNEL_DATA, then EOF/exit-status/CLOSE."
  (let* ((co (expect-msg conn +msg-channel-open+ "CHANNEL_OPEN"))
         (cr (make-reader co 1))
         (ctype (r-cstring cr))
         (peer (r-u32 cr)))                              ; client's channel id
    (declare (ignore ctype))
    (let ((chan 0))                                      ; our channel id
      (let ((w (make-writer)))                           ; OPEN_CONFIRMATION
        (w-byte w +msg-channel-open-confirmation+)
        (w-u32 w peer) (w-u32 w chan) (w-u32 w #x100000) (w-u32 w 32768)
        (write-packet conn (writer-bytes w)))
      (loop
        (let* ((p (read-payload conn)) (msg (aref p 0)))
          (cond
            ((= msg +msg-channel-request+)
             (let* ((r (make-reader p 1)) (rchan (r-u32 r)) (rtype (r-cstring r))
                    (want-reply (r-bool r)))
               (declare (ignore rchan))
               (cond
                 ((or (string= rtype "exec") (string= rtype "shell"))
                  (let ((command (if (string= rtype "exec") (r-cstring r) nil)))
                    (when want-reply
                      (let ((w (make-writer)))
                        (w-byte w +msg-channel-success+) (w-u32 w peer)
                        (write-packet conn (writer-bytes w))))
                    (multiple-value-bind (out code)
                        (funcall exec-handler command)
                      (server-write-channel-data conn peer (string->utf8 (or out "")))
                      (let ((w (make-writer)))            ; exit-status
                        (w-byte w +msg-channel-request+) (w-u32 w peer)
                        (w-string w "exit-status") (w-bool w nil) (w-u32 w (or code 0))
                        (write-packet conn (writer-bytes w)))
                      (let ((w (make-writer)))            ; EOF then CLOSE
                        (w-byte w +msg-channel-eof+) (w-u32 w peer)
                        (write-packet conn (writer-bytes w)))
                      (let ((w (make-writer)))
                        (w-byte w +msg-channel-close+) (w-u32 w peer)
                        (write-packet conn (writer-bytes w)))
                      ;; graceful close: let the client drain our output and send
                      ;; its own CLOSE before we tear the socket down (else a
                      ;; premature close RSTs the client's unread receive buffer)
                      (handler-case
                          (loop for q = (read-payload conn)
                                until (= (aref q 0) +msg-channel-close+))
                        (error () nil))
                      (return))))
                 (want-reply
                  (let ((w (make-writer)))
                    (w-byte w +msg-channel-failure+) (w-u32 w peer)
                    (write-packet conn (writer-bytes w)))))))
            ((= msg +msg-channel-eof+))
            ((= msg +msg-channel-close+) (return))
            ((= msg +msg-channel-data+))                 ; ignore client stdin for exec
            ((= msg +msg-channel-window-adjust+))))))))

;;; ---- top-level ---------------------------------------------------------------

(defun serve-connection (conn host-secret host-public &key authorized-keys exec)
  "Run the full server handshake on an accepted CONN and service one session."
  (unwind-protect
       (progn
         (server-exchange-versions conn)
         (server-do-kex conn host-secret host-public)
         (server-authenticate conn :authorized-keys authorized-keys)
         (server-serve-session conn (or exec (lambda (cmd) (declare (ignore cmd)) ""))))
    (ignore-errors (send-raw conn #()))
    (ignore-errors (sb-bsd-sockets:socket-close (ssh-conn-socket conn)))))

(defun serve (port &key host-key authorized-keys exec (once nil))
  "Serve SSH on PORT.  HOST-KEY is the path to an unencrypted OpenSSH Ed25519
   host private key.  AUTHORIZED-KEYS restricts which client keys may log in (a
   list of 32-byte public keys or blobs; NIL accepts any key with a valid
   signature).  EXEC is called with the requested command (a string, or NIL for
   an interactive shell) and returns the output string (optionally a second value
   exit code).  With :ONCE, serve exactly one connection and return."
  (multiple-value-bind (host-secret host-public) (load-private-key host-key)
    (let ((listen (tcp-listen port)))
      (format *error-output* "~&conch: SSH server listening on port ~d~%" port)
      (force-output *error-output*)
      (unwind-protect
           (loop
             (let ((conn (accept-conn listen)))
               (if once
                   (progn (serve-connection conn host-secret host-public
                                            :authorized-keys authorized-keys :exec exec)
                          (return))
                   (handler-case
                       (serve-connection conn host-secret host-public
                                         :authorized-keys authorized-keys :exec exec)
                     (error () nil)))))            ; a bad connection shouldn't kill the server
        (ignore-errors (sb-bsd-sockets:socket-close listen))))))
