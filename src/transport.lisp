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
(defconstant +msg-kex-ecdh-init+ 30)
(defconstant +msg-kex-ecdh-reply+ 31)

(defstruct ssh-conn
  socket
  stream
  (client-id "" :type string)
  (server-id "" :type string)
  (send-seq 0 :type (unsigned-byte 32))
  (recv-seq 0 :type (unsigned-byte 32))
  send-cipher                            ; NIL (plaintext) or a cipher object
  recv-cipher
  session-id                             ; H of the first key exchange
  server-host-key)                       ; the verified host public key blob

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

(defun send-raw (conn bytes)
  (write-sequence bytes (ssh-conn-stream conn))
  (force-output (ssh-conn-stream conn)))

(defun read-exact (conn n)
  (let* ((buf (make-array n :element-type '(unsigned-byte 8)))
         (got (read-sequence buf (ssh-conn-stream conn))))
    (unless (= got n)
      (ssh-protocol-error "short read (~d of ~d bytes) — connection closed" got n))
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
(defun write-packet (conn payload)
  "Frame, (encrypt,) and send PAYLOAD (a byte vector whose first byte is the
   message number)."
  (if (ssh-conn-send-cipher conn)
      (cipher-send-packet conn payload)
      (plaintext-send-packet conn payload))
  (setf (ssh-conn-send-seq conn) (logand (1+ (ssh-conn-send-seq conn)) #xffffffff)))

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

(defun plaintext-recv-packet (conn)
  (let* ((plen (be->integer (read-exact conn 4)))
         (rest (read-exact conn plen))
         (pad (aref rest 0)))
    (subseq rest 1 (- plen pad))))

;;; A read-packet that transparently drops transport housekeeping messages the
;;; higher layers don't care about (IGNORE/DEBUG), and surfaces DISCONNECT.
(defun read-payload (conn)
  (loop for p = (read-packet conn)
        for msg = (aref p 0)
        do (cond ((= msg +msg-ignore+))
                 ((= msg +msg-debug+))
                 ((= msg +msg-disconnect+)
                  (let ((r (make-reader p 1)))
                    (let ((code (r-u32 r)) (desc (r-cstring r)))
                      (ssh-protocol-error "server disconnected (~d): ~a" code desc))))
                 (t (return p)))))

(defun expect-msg (conn number what)
  (let ((p (read-payload conn)))
    (unless (= (aref p 0) number)
      (ssh-protocol-error "expected ~a (~d), got message ~d" what number (aref p 0)))
    p))
