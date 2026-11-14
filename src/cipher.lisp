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

(defun cipher-send-packet (conn payload)
  "PAYLOAD as one packet: built in a single buffer -- length, padding length, payload, padding, room for the
   tag -- encrypted there, MACed there, sent from there.  (Built from parts and joined, an upload's every
   chunk was copied five more times.)"
  (let* ((cip (ssh-conn-send-cipher conn))
         (nonce (%seq-nonce (ssh-conn-send-seq conn)))
         (payload (to-u8v payload))
         (plen (length payload))
         ;; pad the body (padlen ‖ payload ‖ padding) to a multiple of 8, >=4 pad;
         ;; the 4-byte length field is NOT part of this block alignment
         (pad (let ((p (- 8 (mod (+ 1 plen) 8)))) (if (< p 4) (+ p 8) p)))
         (pktlen (+ 1 plen pad))
         (buf (make-array (+ 4 pktlen 16) :element-type '(unsigned-byte 8)))
         (polykey (subseq (n:chacha20-original-block (occ-main cip) 0 nonce) 0 32)))
    (dotimes (i 4) (setf (aref buf i) (logand (ash pktlen (* -8 (- 3 i))) #xff)))
    (setf (aref buf 4) pad)
    (replace buf payload :start1 5)
    (%random-padding cip buf (+ 5 plen) pad)
    (n:chacha20-original-xor (occ-header cip) nonce buf :end 4 :counter 0)
    (n:chacha20-original-xor (occ-main cip) nonce buf :start 4 :end (+ 4 pktlen) :counter 1)
    (replace buf (n:poly1305-mac polykey buf :end (+ 4 pktlen)) :start1 (+ 4 pktlen))
    (send-raw conn buf)))

(defun cipher-recv-packet (conn)
  (let* ((cip (ssh-conn-recv-cipher conn))
         (nonce (%seq-nonce (ssh-conn-recv-seq conn)))
         (enc-len (read-exact conn 4))
         (pktlen (be->integer
                  (n:chacha20-original (occ-header cip) nonce enc-len :counter 0))))
    (when (or (< pktlen 8) (> pktlen (* 256 1024)) (plusp (mod pktlen 8)))
      (ssh-protocol-error "chacha20-poly1305: implausible packet length ~d" pktlen))
    (let* ((enc-body (let ((*mid-packet* t)) (read-exact conn pktlen)))
           (tag (let ((*mid-packet* t)) (read-exact conn 16)))
           (polykey (subseq (n:chacha20-original-block (occ-main cip) 0 nonce) 0 32))
           ;; the MAC is over the encrypted length and body together: one buffer, decrypted in place after
           (buf (let ((b (make-array (+ 4 pktlen) :element-type '(unsigned-byte 8))))
                  (replace b enc-len) (replace b enc-body :start1 4) b))
           (want (n:poly1305-mac polykey buf)))
      (unless (n:bytes= want tag)
        (ssh-protocol-error "chacha20-poly1305: MAC verification failed"))
      (n:chacha20-original-xor (occ-main cip) nonce buf :start 4 :counter 1)
      (let ((pad (aref buf 4)))
        (subseq buf 5 (- (+ 4 pktlen) pad))))))
