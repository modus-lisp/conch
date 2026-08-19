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

(defconstant +msg-global-request+ 80)
(defconstant +msg-request-failure+ 82)

(defparameter *forward-connect-timeout* 10
  "Seconds to wait for a direct-tcpip forward to reach its target.")

(defun server-serve-session (conn handler)
  "Backwards-compatible single-session entry point.  See SERVER-SERVE-CHANNELS."
  (serve-channels conn handler))

;;; A connection carries several channels at once: one session, plus a
;;; direct-tcpip channel for every `ssh -L` stream the client opens.  So the read
;;; loop below owns the socket and does nothing slow — it routes packets and
;;; hands the slow parts (the session handler, and each forward's local->remote
;;; pump) to their own threads.  Writes from those threads are safe because
;;; WRITE-PACKET serialises on the connection's send lock.
;;;
;;; That also fixes a deadlock the single-channel version had: HANDLER was called
;;; from inside the read loop, so a handler writing more than the initial window
;;; could never receive the WINDOW_ADJUST that would let it continue.

(defun serve-channels (conn handler &key (allow-forwarding t))
  "Service every channel the client opens until it hangs up.

   Session channels are handed to HANDLER (command chan -> exit-code) on their own
   thread; CHAN-PTY holds the client's terminal if it asked for one.  With
   ALLOW-FORWARDING (the default, matching OpenSSH's AllowTcpForwarding), the
   client may also open direct-tcpip channels — this is what `ssh -L` uses, and
   it lets an authenticated client reach anything routable from this process."
  (let ((chans (make-hash-table :test 'eql))
        (next-local 0)
        (threads '()))
    (labels
        ((send (&rest parts)
           (let ((w (make-writer)))
             (loop for (kind val) on parts by #'cddr
                   do (ecase kind
                        (:byte (w-byte w val)) (:u32 (w-u32 w val))
                        (:string (w-string w val)) (:bool (w-bool w val))))
             (write-packet conn (writer-bytes w))))
         (reply (ok peer)
           (send :byte (if ok +msg-channel-success+ +msg-channel-failure+) :u32 peer))
         (open-confirm (peer local)
           (send :byte +msg-channel-open-confirmation+ :u32 peer :u32 local
                 :u32 *initial-window* :u32 *max-packet*))
         (open-fail (peer reason text)
           (send :byte +msg-channel-open-failure+ :u32 peer :u32 reason
                 :string (string->utf8 text) :string (string->utf8 "")))
         (new-chan (peer window max)
           (let ((c (make-chan :conn conn :local-id next-local :remote-id peer
                               :send-window window :send-max max
                               :recv-window *initial-window*
                               :server-side t)))
             (setf (gethash next-local chans) c)
             (incf next-local)
             c))
         (finish-chan (c code)
           (ignore-errors
            (send :byte +msg-channel-request+ :u32 (chan-remote-id c)
                  :string (string->utf8 "exit-status") :bool nil :u32 (or code 0)))
           (unless (chan-eof c) (ignore-errors (chan-send-eof c)))
           (ignore-errors (chan-close c))
           (remhash (chan-local-id c) chans)))

      (unwind-protect
           (loop
             (let* ((p (handler-case (read-payload conn) (error () nil))))
               (unless p (return))
               (let ((msg (aref p 0)) (r (make-reader p 1)))
                 (cond

                   ;; ---- a new channel ------------------------------------------
                   ((= msg +msg-channel-open+)
                    (let* ((ctype (r-cstring r)) (peer (r-u32 r))
                           (window (r-u32 r)) (max (r-u32 r)))
                      (cond
                        ((string= ctype "session")
                         (open-confirm peer (chan-local-id (new-chan peer window max))))

                        ((string= ctype "direct-tcpip")
                         ;; RFC 4254 s7.2: host/port to reach, then the originator.
                         (let ((host (r-cstring r)) (port (r-u32 r)))
                           (if (not allow-forwarding)
                               (open-fail peer 1 "forwarding disabled")
                               (handler-case
                                   (let ((sock (tcp-connect-timeout host port)))
                                     (let ((c (new-chan peer window max)))
                                       (setf (chan-socket c) sock)
                                       (open-confirm peer (chan-local-id c))
                                       ;; target -> client, on its own thread; the
                                       ;; other direction is routed by this loop.
                                       (push (sb-thread:make-thread
                                              (lambda () (forward-pump c))
                                              :name (format nil "conch-forward ~a:~d" host port))
                                             threads)))
                                 (error (e)
                                   (declare (ignore e))
                                   (open-fail peer 2 (format nil "connect to ~a:~d failed" host port))))))) 

                        (t (open-fail peer 3 (format nil "unknown channel type ~a" ctype))))))

                   ;; ---- a request on a channel ---------------------------------
                   ((= msg +msg-channel-request+)
                    (let* ((local (r-u32 r)) (rtype (r-cstring r)) (want-reply (r-bool r))
                           (c (gethash local chans)))
                      (cond
                        ((null c) (when want-reply (reply nil 0)))

                        ;; The client's terminal.  We do not allocate a real pty —
                        ;; nothing here execs a foreign program that would need one —
                        ;; we record what the client told us, which is exactly what an
                        ;; in-process TUI needs in order to draw.
                        ((string= rtype "pty-req")
                         (let ((term (r-cstring r)) (cols (r-u32 r)) (rows (r-u32 r))
                               (wpx (r-u32 r)) (hpx (r-u32 r)) (modes (r-string r)))
                           (setf (chan-pty c)
                                 (make-pty :term term :cols cols :rows rows
                                           :width-px wpx :height-px hpx :modes modes))
                           (when want-reply (reply t (chan-remote-id c)))))

                        ((string= rtype "window-change")
                         (let ((cols (r-u32 r)) (rows (r-u32 r))
                               (wpx (r-u32 r)) (hpx (r-u32 r)))
                           (let ((pty (chan-pty c)))
                             (when pty
                               (setf (pty-cols pty) cols (pty-rows pty) rows
                                     (pty-width-px pty) wpx (pty-height-px pty) hpx)
                               (when (pty-on-resize pty)
                                 (ignore-errors (funcall (pty-on-resize pty) cols rows)))))
                           ;; window-change is specified to carry want_reply false.
                           (when want-reply (reply t (chan-remote-id c)))))

                        ((or (string= rtype "exec") (string= rtype "shell"))
                         (let ((command (if (string= rtype "exec") (r-cstring r) nil)))
                           (when want-reply (reply t (chan-remote-id c)))
                           (push (sb-thread:make-thread
                                  (lambda ()
                                    (finish-chan
                                     c (handler-case (funcall handler command c)
                                         (error () 1))))
                                  :name "conch-session")
                                 threads)))

                        ;; env, signal, subsystem, x11-req, ...: politely no.
                        (want-reply (reply nil (chan-remote-id c))))))

                   ;; ---- data and lifecycle, routed to the owning channel --------
                   ((or (= msg +msg-channel-data+) (= msg +msg-channel-extended-data+)
                        (= msg +msg-channel-window-adjust+) (= msg +msg-channel-eof+)
                        (= msg +msg-channel-close+))
                    (let* ((local (r-u32 (make-reader p 1)))
                           (c (gethash local chans)))
                      (when c
                        (chan-process c p)
                        ;; A forward's client->target direction: whatever just
                        ;; arrived goes straight out the socket.
                        (when (chan-socket c)
                          (cond ((= msg +msg-channel-data+) (forward-drain c))
                                ((or (= msg +msg-channel-eof+) (= msg +msg-channel-close+))
                                 (ignore-errors
                                  (sb-bsd-sockets:socket-close (chan-socket c))))))
                        (when (= msg +msg-channel-close+)
                          (sb-thread:with-mutex ((chan-window-lock c))
                            (sb-thread:condition-broadcast (chan-window-cv c)))
                          (remhash local chans)))))

                   ;; A global request (no-more-sessions@openssh.com, tcpip-forward
                   ;; for `ssh -R`, ...).  We implement none, and a want_reply left
                   ;; unanswered hangs the client, so always refuse explicitly.
                   ((= msg +msg-global-request+)
                    (let ((name (r-cstring r)) (want-reply (r-bool r)))
                      (declare (ignore name))
                      (when want-reply (send :byte +msg-request-failure+))))

                   (t nil)))))

        (dolist (c (loop for v being the hash-values of chans collect v))
          (ignore-errors (when (chan-socket c) (sb-bsd-sockets:socket-close (chan-socket c)))))
        (dolist (th threads) (ignore-errors (sb-thread:join-thread th :timeout 2)))))))

;;; ---- direct-tcpip plumbing --------------------------------------------------

(defun tcp-connect-timeout (host port)
  "Connect to HOST:PORT, giving up rather than hanging a channel open forever."
  (let ((sock (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (handler-case
        (progn (sb-bsd-sockets:socket-connect sock (resolve-address host) port) sock)
      (error (e) (ignore-errors (sb-bsd-sockets:socket-close sock)) (error e)))))

(defun forward-drain (c)
  "Everything buffered on the channel goes out to the forward's socket."
  (let ((n (chan-avail c)))
    (when (plusp n)
      (let ((bytes (subseq (chan-in c) (chan-in-pos c) (+ (chan-in-pos c) n))))
        (incf (chan-in-pos c) n)
        (handler-case (sb-bsd-sockets:socket-send (chan-socket c) bytes (length bytes))
          (error () (ignore-errors (chan-close c))))))))

(defun forward-pump (c)
  "Target -> client, until either end goes away."
  (let ((buf (make-array 32768 :element-type '(unsigned-byte 8))))
    (unwind-protect
         (loop
           (multiple-value-bind (data n)
               (handler-case (sb-bsd-sockets:socket-receive (chan-socket c) buf nil)
                 (error () (values nil 0)))
             (declare (ignore data))
             (when (or (null n) (zerop n)) (return))
             (handler-case (chan-write c (subseq buf 0 n))
               (error () (return)))))
      (ignore-errors (sb-bsd-sockets:socket-close (chan-socket c)))
      (ignore-errors (chan-send-eof c))
      (ignore-errors (chan-close c)))))

;;; ---- top-level ---------------------------------------------------------------

(defun exec->handler (exec)
  "Adapt a one-shot EXEC (command -> (values output exit-code)) to a streaming
   session handler (command chan -> exit-code)."
  (lambda (command chan)
    (multiple-value-bind (out code)
        (funcall (or exec (lambda (c) (declare (ignore c)) "")) command)
      (chan-write chan (string->utf8 (or out "")))
      (or code 0))))

(defun serve-connection (conn host-secret host-public
                         &key authorized-keys exec handler (allow-forwarding t))
  "Run the full server handshake on an accepted CONN and service one session with
   HANDLER (command chan -> exit-code) or, if none, the one-shot EXEC."
  (unwind-protect
       (progn
         (server-exchange-versions conn)
         (server-do-kex conn host-secret host-public)
         (server-authenticate conn :authorized-keys authorized-keys)
         (serve-channels conn (or handler (exec->handler exec))
                                 :allow-forwarding allow-forwarding))
    (ignore-errors (send-raw conn #()))
    (ignore-errors (sb-bsd-sockets:socket-close (ssh-conn-socket conn)))))

(defun serve (port &key host-key authorized-keys exec handler (once nil)
                          (allow-forwarding t))
  "Serve SSH on PORT.  HOST-KEY is the path to an unencrypted OpenSSH Ed25519
   host private key.  AUTHORIZED-KEYS restricts which client keys may log in (a
   list of 32-byte public keys or blobs; NIL accepts any key with a valid
   signature).  HANDLER (command chan -> exit-code) services each session with a
   duplex channel — for interactive protocols like git-over-SSH; EXEC (command ->
   (values output exit-code)) is the simple one-shot form.  With :ONCE, serve
   exactly one connection and return.

   ALLOW-FORWARDING (default T, as OpenSSH's AllowTcpForwarding is) lets an
   authenticated client open direct-tcpip channels — `ssh -L`.  That reaches
   anything routable from this process, so pass NIL where the login is meant to
   be confined to the session itself."
  (multiple-value-bind (host-secret host-public) (load-private-key host-key)
    (let ((listen (tcp-listen port)))
      (format *error-output* "~&conch: SSH server listening on port ~d~%" port)
      (force-output *error-output*)
      (unwind-protect
           (loop
             (let ((conn (accept-conn listen)))
               (flet ((handle () (serve-connection conn host-secret host-public
                                                    :authorized-keys authorized-keys
                                                    :exec exec :handler handler
                                                    :allow-forwarding allow-forwarding)))
                 (if once
                     (progn (handle) (return))
                     ;; A thread per connection.  Serving them one at a time meant
                     ;; a single long-lived client — an `ssh -N` tunnel, or anyone
                     ;; sitting in an interactive session — blocked every later
                     ;; login until it hung up.  One bad connection still must not
                     ;; kill the server, hence the handler-case inside.
                     (sb-thread:make-thread
                      (lambda () (handler-case (handle) (error () nil)))
                      :name "conch-connection")))))
        (ignore-errors (sb-bsd-sockets:socket-close listen))))))
