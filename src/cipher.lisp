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
  (header nil :type n:u8v))   ; K_1 — length-field cipher          (key bytes 32..63)

(defun make-openssh-cipher (key64)
  (make-occ :main (subseq key64 0 32) :header (subseq key64 32 64)))

(defun %seq-nonce (seq)
  "The 8-byte big-endian packet sequence number used as the ChaCha20 nonce."
  (let ((b (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 b) (setf (aref b i) (logand (ash seq (* -8 (- 7 i))) #xff)))))

(defun u32be (v)
  (let ((b (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 b) (setf (aref b i) (logand (ash v (* -8 (- 3 i))) #xff)))))

(defun cipher-send-packet (conn payload)
  (let* ((cip (ssh-conn-send-cipher conn))
         (nonce (%seq-nonce (ssh-conn-send-seq conn)))
         (plen (length payload))
         ;; pad the body (padlen ‖ payload ‖ padding) to a multiple of 8, >=4 pad;
         ;; the 4-byte length field is NOT part of this block alignment
         (pad (let ((p (- 8 (mod (+ 1 plen) 8)))) (if (< p 4) (+ p 8) p)))
         (pktlen (+ 1 plen pad))
         (body (let ((w (make-writer)))
                 (w-byte w pad) (w-raw w (to-u8v payload)) (w-raw w (n:random-bytes pad))
                 (writer-bytes w)))
         (enc-len (n:chacha20-original (occ-header cip) nonce (u32be pktlen) :counter 0))
         (polykey (subseq (n:chacha20-original-block (occ-main cip) 0 nonce) 0 32))
         (enc-body (n:chacha20-original (occ-main cip) nonce body :counter 1))
         (tag (n:poly1305-mac polykey (n:u8cat enc-len enc-body))))
    (send-raw conn (n:u8cat enc-len enc-body tag))))

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
           (want (n:poly1305-mac polykey (n:u8cat enc-len enc-body))))
      (unless (n:bytes= want tag)
        (ssh-protocol-error "chacha20-poly1305: MAC verification failed"))
      (let* ((body (n:chacha20-original (occ-main cip) nonce enc-body :counter 1))
             (pad (aref body 0)))
        (subseq body 1 (- pktlen pad))))))
