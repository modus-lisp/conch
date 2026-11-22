;;;; cipher.lisp — chacha20-poly1305@openssh.com (OpenSSH PROTOCOL.chacha20poly1305).
;;;;
;;;; 64 bytes of key material per direction split into two 256-bit ChaCha20 keys:
;;;; the first 32 bytes (K_2, "main") encrypt the packet body and derive the
;;;; Poly1305 key; the second 32 bytes (K_1, "header") encrypt the 4-byte packet
;;;; length field on its own.  The nonce is the packet sequence number as a
;;;; uint64 big-endian.  Poly1305 authenticates (encrypted length ‖ encrypted
;;;; body); the tag is verified before the body is decrypted or processed.

(in-package #:conch)

(defstruct occ
  (main nil :type n:u8v)      ; K_2 — body cipher + Poly1305 key   (key bytes 0..31)
  (header nil :type n:u8v)    ; K_1 — length-field cipher          (key bytes 32..63)
  ;; random bytes for packets' padding, drawn a few KB at a time: one RANDOM-BYTES call per packet cost
  ;; more than a packet's encryption is meant to (137 us each on modus)
  (pool (make-array 0 :element-type '(unsigned-byte 8)) :type n:u8v)
  (pool-at 0 :type fixnum))

(defun make-openssh-cipher (key64)
  (make-occ :main (subseq key64 0 32) :header (subseq key64 32 64)))

(defun %seq-nonce (seq)
  "The 8-byte big-endian packet sequence number used as the ChaCha20 nonce."
  (let ((b (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 b) (setf (aref b i) (logand (ash seq (* -8 (- 7 i))) #xff)))))

(defun u32be (v)
  (let ((b (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 b) (setf (aref b i) (logand (ash v (* -8 (- 3 i))) #xff)))))

(defun %random-padding (cip buf start n)
  "N random bytes into BUF at START, from CIP's pool."
  (when (> (+ (occ-pool-at cip) n) (length (occ-pool cip)))
    (setf (occ-pool cip) (n:random-bytes 4096) (occ-pool-at cip) 0))
  (replace buf (occ-pool cip) :start1 start :start2 (occ-pool-at cip) :end2 (+ (occ-pool-at cip) n))
  (incf (occ-pool-at cip) n))

(defun cipher-send-packet (conn payload &optional (end (length payload)))
  "PAYLOAD as one packet: built in a single buffer -- length, padding length, payload, padding, room for the
   tag -- encrypted there, MACed there, sent from there.  (Built from parts and joined, an upload's every
   chunk was copied five more times.)  The buffer is the connection's, kept: the caller holds SEND-LOCK."
  (let* ((cip (ssh-conn-send-cipher conn))
         (nonce (%seq-nonce (ssh-conn-send-seq conn)))
         (payload (to-u8v payload))
         (plen end)
         ;; pad the body (padlen ‖ payload ‖ padding) to a multiple of 8, >=4 pad;
         ;; the 4-byte length field is NOT part of this block alignment
         (pad (let ((p (- 8 (mod (+ 1 plen) 8)))) (if (< p 4) (+ p 8) p)))
         (pktlen (+ 1 plen pad))
         (buf (%conn-room conn :send (+ 4 pktlen 16)))
         (polykey (subseq (n:chacha20-original-block (occ-main cip) 0 nonce) 0 32)))
    (dotimes (i 4) (setf (aref buf i) (logand (ash pktlen (* -8 (- 3 i))) #xff)))
    (setf (aref buf 4) pad)
    (replace buf payload :start1 5 :end2 plen)
    (%random-padding cip buf (+ 5 plen) pad)
    (n:chacha20-original-xor (occ-header cip) nonce buf :end 4 :counter 0)
    (n:chacha20-original-xor (occ-main cip) nonce buf :start 4 :end (+ 4 pktlen) :counter 1)
    (replace buf (n:poly1305-mac polykey buf :end (+ 4 pktlen)) :start1 (+ 4 pktlen))
    (send-raw conn buf (+ 4 pktlen 16))))

(defun %tag-ok-p (want buf at)
  "WANT (16 bytes) equal to BUF[AT,AT+16), in constant time."
  (let ((d 0))
    (dotimes (i 16 (zerop d)) (setf d (logior d (logxor (aref want i) (aref buf (+ at i))))))))

(defun cipher-recv-packet (conn)
  "The next packet's payload, a fresh vector."
  (multiple-value-bind (buf start end) (cipher-recv-in-place conn)
    (subseq buf start end)))

(defun cipher-recv-in-place (conn)
  "The next packet's payload where it was decrypted: (values BUF START END), BUF the connection's own, good
   until the next read.  The packet (encrypted length, body, tag) is read into it, checked and decrypted
   there.  (Read in parts and joined, a download's every packet was copied twice more.)"
  (let* ((cip (ssh-conn-recv-cipher conn))
         (nonce (%seq-nonce (ssh-conn-recv-seq conn)))
         (buf (let ((b (ssh-conn-recv-buf conn)))
                (if (>= (length b) 4096) b
                    (setf (ssh-conn-recv-buf conn) (make-array 36000 :element-type '(unsigned-byte 8))))))
         (pktlen (progn (read-exact-into conn buf 0 4)
                        (be->integer (n:chacha20-original (occ-header cip) nonce (subseq buf 0 4) :counter 0)))))
    (when (or (< pktlen 8) (> pktlen (* 256 1024)) (plusp (mod pktlen 8)))
      (ssh-protocol-error "chacha20-poly1305: implausible packet length ~d" pktlen))
    (let ((need (+ 4 pktlen 16)))
      (when (< (length buf) need)
        (let ((new (make-array need :element-type '(unsigned-byte 8))))
          (replace new buf :end2 4)
          (setf buf new (ssh-conn-recv-buf conn) new)))
      (let ((*mid-packet* t)) (read-exact-into conn buf 4 need))
      ;; the MAC is over the encrypted length and body together; the tag follows them
      (let ((polykey (subseq (n:chacha20-original-block (occ-main cip) 0 nonce) 0 32)))
        (unless (%tag-ok-p (n:poly1305-mac polykey buf :end (+ 4 pktlen)) buf (+ 4 pktlen))
          (ssh-protocol-error "chacha20-poly1305: MAC verification failed")))
      (n:chacha20-original-xor (occ-main cip) nonce buf :start 4 :end (+ 4 pktlen) :counter 1)
      (let ((pad (aref buf 4)))
        (values buf 5 (- (+ 4 pktlen) pad))))))
