;;;; transport.lisp — SSH transport: TCP, version exchange, packet framing.
;;;;
;;;; RFC 4253.  A connection carries the socket, the two version identification
;;;; strings (needed later in the key-exchange hash), per-direction packet
;;;; sequence numbers, and per-direction cipher state (NIL = the initial
;;;; plaintext phase; a cipher object once NEWKEYS takes effect).

(in-package #:conch)

;;; SSH message numbers (RFC 4253 §12, RFC 4252, RFC 4254)
(defconstant +msg-disconnect+ 1)
(defconstant +msg-ignore+ 2)
(defconstant +msg-unimplemented+ 3)
(defconstant +msg-debug+ 4)
(defconstant +msg-service-request+ 5)
(defconstant +msg-service-accept+ 6)
(defconstant +msg-kexinit+ 20)
(defconstant +msg-newkeys+ 21)
(defconstant +msg-global-request+ 80)
(defconstant +msg-request-success+ 81)
(defconstant +msg-request-failure+ 82)
(defconstant +msg-kex-ecdh-init+ 30)
(defconstant +msg-kex-ecdh-reply+ 31)

(defstruct ssh-conn
  socket
  stream
  ;; A connection through a JUMP HOST has no socket: VIA is a direct-tcpip channel on the jump host's
  ;; connection, and the bytes go through it.  JUMP is that connection, owned (closed with this one) once
  ;; this one is up.
  via
  jump
  ;; the client's channels, by their local id: a connection carries several at once (an SFTP session, a
  ;; command beside it, a tunnel), and a message read for one is handed to the one it is for
  (chans (make-hash-table))
  (next-chan 0)
  (client-id "" :type string)
  (server-id "" :type string)
  (send-seq 0 :type (unsigned-byte 32))
  (recv-seq 0 :type (unsigned-byte 32))
  send-cipher                            ; NIL (plaintext) or a cipher object
  recv-cipher
  session-id                             ; H of the first key exchange
  server-host-key                        ; the verified host public key blob
  ;; One connection now carries several channels at once — a session and any
  ;; number of forwarded TCP streams — and each is pumped by its own thread.  The
  ;; send path is not re-entrant (a packet is framed, encrypted and counted
  ;; against SEND-SEQ, and interleaving two of those corrupts the stream and
  ;; desynchronises the cipher), so every writer takes this first.
  (send-lock (sb-thread:make-mutex :name "conch-send"))
  ;; where each packet is read and decrypted: kept, so a download is not a fresh vector a packet
  (recv-buf (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  ;; where each packet is built to be sent, and each channel-data payload before it: kept too (both are used
  ;; under SEND-LOCK only, and done with once the packet is written)
  (send-buf (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (data-buf (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*))))

(defun %conn-room (conn slot n)
  "The connection's buffer SLOT (:send or :data), at least N bytes long."
  (let ((b (if (eq slot :send) (ssh-conn-send-buf conn) (ssh-conn-data-buf conn))))
    (if (>= (length b) n) b
        (let ((new (make-array (max n 36000) :element-type '(unsigned-byte 8))))
          (if (eq slot :send) (setf (ssh-conn-send-buf conn) new) (setf (ssh-conn-data-buf conn) new))))))

;;; ---- socket I/O ------------------------------------------------------------
(defun resolve-address (host)
  (handler-case (sb-bsd-sockets:make-inet-address host)   ; dotted quad
    (error ()
      (sb-bsd-sockets:host-ent-address (sb-bsd-sockets:get-host-by-name host)))))

(defun tcp-connect (host port)
  (let ((sock (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (sb-bsd-sockets:socket-connect sock (resolve-address host) port)
    (values sock (sb-bsd-sockets:socket-make-stream
                  sock :input t :output t :element-type '(unsigned-byte 8)
                  :buffering :none))))

(defun send-raw (conn bytes &optional (end (length bytes)))
  (if (ssh-conn-via conn)
      (chan-write (ssh-conn-via conn) bytes end)
      (progn (write-sequence bytes (ssh-conn-stream conn) :end end)
             (force-output (ssh-conn-stream conn)))))

(defvar *mid-packet* nil
  "True while a packet is partly read: its first bytes are in, the rest are not.  Not a SAFE POINT.")
(defvar *mid-sftp* nil
  "True while an SFTP message is partly read or partly written (sftp.lisp).  Not a SAFE POINT.")

(defun at-safe-point-p ()
  "True when conch is waiting for the first bytes of a packet, with no packet and no SFTP message half
   read or half written: the moment *WAIT-HOOK* may itself use the connection -- send SFTP requests and
   read their responses (SFTP-RESPONSE sets aside, by request id, any it reads that are not its own).
   Anywhere else, another request would split a packet or a message in two."
  (not (or *mid-packet* *mid-sftp*)))

(defvar *rescan* nil
  "While an SFTP response is waited for: a function true once that response has turned up some other way --
   read and set aside by what a *WAIT-HOOK* did -- so the wait stops reading the socket for it.")

(defvar *wait-hook* nil
  "NIL, or a function of no arguments called about every 20 ms while a read waits for the server:
   an app's way to keep its UI alive and to let its user give up.  Returning :ABORT ends the wait
   with an SSH-ERROR \"cancelled\" -- at the next SAFE POINT, so the connection stays usable (what was in
   flight is drained by whatever was waiting for it).")

(defun await-input (conn)
  "Return once CONN has input (or has closed), calling *WAIT-HOOK* while it waits.  Not while it runs: what
   the hook does on the connection itself waits plainly, or every wait inside it would call it again."
  (let* ((s (ssh-conn-stream conn))
         (fd (ignore-errors (sb-sys:fd-stream-fd s)))
         (hook *wait-hook*))
    (loop until (or (listen s)
                    (if fd (sb-sys:wait-until-fd-usable fd :input 0.02) (progn (sleep 0.02) nil)))
          do (when (and (eq (let ((*wait-hook* nil)) (funcall hook)) :abort)
                        ;; only where nothing is half read: a cancel must leave the connection usable --
                        ;; anywhere else it waits the moment it takes to get to one
                        (at-safe-point-p))
               (error 'ssh-error :message "cancelled"))
             ;; the hook may have read what this wait is for; at a safe point nothing is half read, so the
             ;; wait can simply be abandoned (SFTP-RESPONSE looks again)
             (when (and *rescan* (at-safe-point-p) (funcall *rescan*))
               (throw 'sftp-rescan nil)))))

(defun read-exact (conn n)
  ;; through a jump host: the bytes come from the tunnel, whose waits are the jump connection's reads -- and
  ;; those call *WAIT-HOOK*, and cancel only at a safe point, as any read does (the special variables that
  ;; say "mid-packet" are bound by this connection's reads as much as by the jump connection's)
  (when (ssh-conn-via conn)
    (return-from read-exact (chan-read-exact (ssh-conn-via conn) n)))
  (when *wait-hook* (await-input conn))
  (let* ((buf (make-array n :element-type '(unsigned-byte 8)))
         (got (read-sequence buf (ssh-conn-stream conn))))
    (unless (= got n)
      (ssh-protocol-error "short read (~d of ~d bytes) — connection closed" got n))
    buf))

(defun read-exact-into (conn buf start end)
  "BUF[START,END) filled from CONN, as READ-EXACT reads (its waits, its tunnel); returns BUF."
  (when (ssh-conn-via conn)
    (return-from read-exact-into (chan-read-into (ssh-conn-via conn) buf start end)))
  (when *wait-hook* (await-input conn))
  (let ((got (read-sequence buf (ssh-conn-stream conn) :start start :end end)))
    (unless (= got end)
      (ssh-protocol-error "short read (~d of ~d bytes) — connection closed" (- got start) (- end start)))
    buf))

;;; ---- version exchange (RFC 4253 §4.2) --------------------------------------
(defparameter *client-id* "SSH-2.0-conch_0.1"
  "Our identification string (without the trailing CR LF).")

(defun read-id-line (conn)
  "Read one CR-LF (or LF) terminated line, returned without the terminator."
  (let ((acc (make-array 32 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for b = (aref (read-exact conn 1) 0)
          until (= b 10)                                   ; LF
          do (unless (= b 13) (vector-push-extend b acc))) ; drop CR
    (utf8->string (coerce acc '(simple-array (unsigned-byte 8) (*))))))

(defun exchange-versions (conn)
  (setf (ssh-conn-client-id conn) *client-id*)
  (send-raw conn (string->utf8 (format nil "~a~c~c" *client-id* #\Return #\Newline)))
  ;; the server may emit banner lines before its SSH- identification
  (loop for line = (read-id-line conn)
        when (and (>= (length line) 4) (string= line "SSH-" :end1 4))
          do (setf (ssh-conn-server-id conn) line)
             (return line)))

;;; ---- binary packet protocol (RFC 4253 §6) ----------------------------------
(defun write-packet (conn payload &optional (end (length payload)))
  "Frame, (encrypt,) and send PAYLOAD (a byte vector whose first byte is the
   message number).  Serialised on the connection's SEND-LOCK: framing and the
   sequence-number bump must be one atomic step, or two channels writing at once
   interleave their packets and desynchronise the cipher."
  (sb-thread:with-recursive-lock ((ssh-conn-send-lock conn))
    (if (ssh-conn-send-cipher conn)
        (cipher-send-packet conn payload end)
        (plaintext-send-packet conn (if (= end (length payload)) payload (subseq payload 0 end))))
    (setf (ssh-conn-send-seq conn) (logand (1+ (ssh-conn-send-seq conn)) #xffffffff))))

(defun plaintext-send-packet (conn payload)
  (let* ((plen (length payload))
         (blk 8)                                    ; block size in the plaintext phase
         (pad (- blk (mod (+ 5 plen) blk)))
         (pad (if (< pad 4) (+ pad blk) pad))
         (w (make-writer)))
    (w-u32 w (+ 1 plen pad))
    (w-byte w pad)
    (w-raw w payload)
    (w-raw w (n:random-bytes pad))
    (send-raw conn (writer-bytes w))))

(defun read-packet (conn)
  "Read (decrypt,) and return the payload byte vector of the next packet."
  (prog1 (if (ssh-conn-recv-cipher conn)
             (cipher-recv-packet conn)
             (plaintext-recv-packet conn))
    (setf (ssh-conn-recv-seq conn) (logand (1+ (ssh-conn-recv-seq conn)) #xffffffff))))

(defun read-packet-in-place (conn)
  "As READ-PACKET, but (values BUF START END): encrypted, the payload where it was decrypted (the connection's
   buffer, good until the next read); before keys, a fresh vector."
  (multiple-value-prog1
      (if (ssh-conn-recv-cipher conn)
          (cipher-recv-in-place conn)
          (let ((p (plaintext-recv-packet conn))) (values p 0 (length p))))
    (setf (ssh-conn-recv-seq conn) (logand (1+ (ssh-conn-recv-seq conn)) #xffffffff))))

(defun plaintext-recv-packet (conn)
  (let* ((plen (be->integer (read-exact conn 4)))
         (rest (let ((*mid-packet* t)) (read-exact conn plen)))
         (pad (aref rest 0)))
    (subseq rest 1 (- plen pad))))

;;; A read-packet that transparently drops transport housekeeping messages the
;;; higher layers don't care about (IGNORE/DEBUG), and surfaces DISCONNECT.
(defun read-payload (conn)
  (loop for p = (read-packet conn)
        do (unless (housekeeping conn p) (return p))))

(defun housekeeping (conn p)
  "True if P was transport housekeeping, now dealt with (IGNORE, DEBUG, a global request); DISCONNECT signals."
  (let ((msg (aref p 0)))
    (cond ((= msg +msg-ignore+) t)
          ((= msg +msg-debug+) t)
          ((= msg +msg-global-request+)          ; e.g. hostkeys-00@openssh.com
           (let ((r (make-reader p 1)))
             (r-cstring r)                        ; request name
             (when (r-bool r)                     ; want_reply → we don't support it
               (write-packet conn (make-array 1 :element-type '(unsigned-byte 8)
                                                :initial-element +msg-request-failure+))))
           t)
          ((= msg +msg-disconnect+)
           (let ((r (make-reader p 1)))
             (let ((code (r-u32 r)) (desc (r-cstring r)))
               (ssh-protocol-error "server disconnected (~d): ~a" code desc))))
          (t nil))))

(defun expect-msg (conn number what)
  (let ((p (read-payload conn)))
    (unless (= (aref p 0) number)
      (ssh-protocol-error "expected ~a (~d), got message ~d" what number (aref p 0)))
    p))
