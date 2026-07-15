;;;; kex.lisp — key exchange: curve25519-sha256 + ssh-ed25519 host keys.
;;;;
;;;; RFC 4253 §7-8 and RFC 8731.  Exchange KEXINITs, run X25519 ECDH, compute the
;;;; exchange hash H, verify the server's Ed25519 signature over H (proving it
;;;; holds the host private key), derive the session keys, and switch on the
;;;; chacha20-poly1305@openssh.com cipher at NEWKEYS.  Honors OpenSSH strict-KEX
;;;; (the Terrapin countermeasure): KEXINIT is sent first and the packet sequence
;;;; numbers reset to zero at NEWKEYS.

(in-package #:conch)

(defparameter *kex-algs*
  '("curve25519-sha256" "curve25519-sha256@libssh.org" "kex-strict-c-v00@openssh.com"))
(defparameter *hostkey-algs*
  '("ssh-ed25519" "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384"
    "rsa-sha2-512" "rsa-sha2-256"))
(defparameter *ciphers* '("chacha20-poly1305@openssh.com"))
(defparameter *macs* '("hmac-sha2-256"))          ; unused with the AEAD cipher
(defparameter *compression* '("none"))

;;; ---- KEXINIT ---------------------------------------------------------------
(defun build-kexinit ()
  (let ((w (make-writer)))
    (w-byte w +msg-kexinit+)
    (w-raw w (n:random-bytes 16))                 ; cookie
    (w-name-list w *kex-algs*)
    (w-name-list w *hostkey-algs*)
    (w-name-list w *ciphers*) (w-name-list w *ciphers*)
    (w-name-list w *macs*) (w-name-list w *macs*)
    (w-name-list w *compression*) (w-name-list w *compression*)
    (w-name-list w '()) (w-name-list w '())       ; languages
    (w-bool w nil)                                 ; first_kex_packet_follows
    (w-u32 w 0)                                    ; reserved
    (writer-bytes w)))

(defun parse-kexinit (payload)
  (let ((r (make-reader payload 1)))              ; skip message byte
    (r-raw r 16)                                  ; cookie
    (list :kex (r-name-list r) :hostkey (r-name-list r)
          :enc-c2s (r-name-list r) :enc-s2c (r-name-list r)
          :mac-c2s (r-name-list r) :mac-s2c (r-name-list r)
          :comp-c2s (r-name-list r) :comp-s2c (r-name-list r))))

(defun negotiate (client server what)
  (or (find-if (lambda (a) (member a server :test #'string=)) client)
      (ssh-error "no common ~a (offered ~a; server ~a)" what client server)))

;;; ---- exchange hash + key derivation ----------------------------------------
(defun mpint-bytes (n)
  (let ((w (make-writer))) (w-mpint w n) (writer-bytes w)))

(defun compute-exchange-hash (conn i-c i-s k-s q-c q-s k)
  "H = SHA256(V_C ‖ V_S ‖ I_C ‖ I_S ‖ K_S ‖ Q_C ‖ Q_S ‖ mpint(K)) — each of the
   first seven fields written as an SSH string."
  (let ((w (make-writer)))
    (w-string w (ssh-conn-client-id conn))
    (w-string w (ssh-conn-server-id conn))
    (w-string w i-c) (w-string w i-s) (w-string w k-s)
    (w-string w q-c) (w-string w q-s)
    (w-mpint w k)
    (n:sha256 (writer-bytes w))))

(defun derive-key (k-mpint h session-id letter nbytes)
  "RFC 4253 §7.2: HASH(K ‖ H ‖ letter ‖ session_id), extended by HASH(K ‖ H ‖
   sofar) until NBYTES are produced."
  (let ((out (n:sha256 (n:u8cat k-mpint h (vector (char-code letter)) session-id))))
    (loop while (< (length out) nbytes)
          do (setf out (n:u8cat out (n:sha256 (n:u8cat k-mpint h out)))))
    (subseq out 0 nbytes)))

;;; ---- host key (ssh-ed25519) ------------------------------------------------
(defun parse-ed25519-blob (blob what)
  "An ssh-ed25519 host-key or signature blob is: string \"ssh-ed25519\" ‖ string
   payload.  Return the payload (32-byte key or 64-byte signature)."
  (let ((r (make-reader blob)))
    (let ((type (r-cstring r)))
      (unless (string= type "ssh-ed25519")
        (ssh-error "expected ssh-ed25519 ~a, got ~a" what type))
      (r-string r))))

(defun host-key-fingerprint (host-key-blob)
  "OpenSSH-style SHA256 fingerprint of a host key blob (\"SHA256:<base64>\")."
  (concatenate 'string "SHA256:" (base64-nopad (n:sha256 (to-u8v host-key-blob)))))

;;; ---- host-key signature verification (ed25519 / RSA / ECDSA) ----------------
(defun verify-host-signature (hk-alg k-s h sig)
  "Verify the server's signature SIG over the exchange hash H using its host key
   blob K-S, per the negotiated host-key algorithm HK-ALG.  T / NIL.  Ed25519 is
   verified with natrium; RSA and ECDSA are verified with the sibling `seal`
   library's primitives."
  (cond
    ((string= hk-alg "ssh-ed25519")
     (n:ed25519-verify (parse-ed25519-blob k-s "host key") h
                       (parse-ed25519-blob sig "signature")))
    ((or (string= hk-alg "rsa-sha2-256") (string= hk-alg "rsa-sha2-512"))
     (verify-rsa-host k-s h sig (if (string= hk-alg "rsa-sha2-512") :sha512 :sha256)))
    ((or (string= hk-alg "ecdsa-sha2-nistp256") (string= hk-alg "ecdsa-sha2-nistp384"))
     (verify-ecdsa-host k-s h sig))
    (t (ssh-error "unsupported host-key algorithm ~a" hk-alg))))

(defun verify-rsa-host (k-s h sig hash-alg)
  "ssh-rsa host key = string \"ssh-rsa\" ‖ mpint e ‖ mpint n; signature blob =
   string \"rsa-sha2-*\" ‖ string raw-signature."
  (let ((kr (make-reader k-s)) (sr (make-reader sig)))
    (unless (string= (r-cstring kr) "ssh-rsa")
      (ssh-error "unexpected RSA host-key blob"))
    (let* ((e (r-mpint kr)) (n (r-mpint kr))
           (key (seal:make-rsa-public-key :n n :e e)))
      (r-cstring sr)                                ; signature type
      (seal:rsa-pkcs1-verify key hash-alg h (r-string sr)))))

(defun verify-ecdsa-host (k-s h sig)
  "ecdsa-sha2-nistpNNN host key = string type ‖ string curve ‖ string Q; signature
   blob = string type ‖ string (mpint r ‖ mpint s)."
  (let ((kr (make-reader k-s)) (sr (make-reader sig)))
    (r-cstring kr)                                  ; "ecdsa-sha2-nistpNNN"
    (let* ((curve-name (r-cstring kr))
           (q (r-string kr))
           (curve (if (string= curve-name "nistp384") seal:*p384* seal:*p256*))
           (digest (if (string= curve-name "nistp384") (n:sha384 h) (n:sha256 h)))
           (point (seal:ec-decode-point curve q)))
      (r-cstring sr)                                ; signature type
      (let ((br (make-reader (r-string sr))))
        (seal:ecdsa-verify curve point digest (r-mpint br) (r-mpint br))))))

;;; ---- the exchange -----------------------------------------------------------
(defun do-kex (conn &key host-key-verifier)
  "Run one key exchange to completion (through NEWKEYS).  HOST-KEY-VERIFIER, if
   given, is called with the host-key blob after the signature checks out — it
   should signal to reject an untrusted host.  Returns H."
  (let ((i-c (build-kexinit)) i-s)
    (write-packet conn i-c)                        ; KEXINIT first (strict-KEX)
    (setf i-s (expect-msg conn +msg-kexinit+ "KEXINIT"))
    (let* ((sk (parse-kexinit i-s))
           (strict (and (member "kex-strict-s-v00@openssh.com" (getf sk :kex) :test #'string=) t)))
      (negotiate *kex-algs* (getf sk :kex) "kex algorithm")
      (negotiate *ciphers* (getf sk :enc-c2s) "cipher")
      (negotiate *ciphers* (getf sk :enc-s2c) "cipher")
      (let ((hk-alg (negotiate *hostkey-algs* (getf sk :hostkey) "host-key algorithm")))
       (multiple-value-bind (priv q-c) (n:x25519-keypair)
        (let ((w (make-writer)))
          (w-byte w +msg-kex-ecdh-init+) (w-string w q-c)
          (write-packet conn (writer-bytes w)))
        (let* ((reply (expect-msg conn +msg-kex-ecdh-reply+ "KEX_ECDH_REPLY"))
               (rr (make-reader reply 1))
               (k-s (r-string rr))                 ; host key blob
               (q-s (r-string rr))                 ; server ephemeral public
               (sig (r-string rr))                 ; signature over H
               (k (be->integer (n:x25519 priv q-s)))
               (h (compute-exchange-hash conn i-c i-s k-s q-c q-s k)))
          (unless (verify-host-signature hk-alg k-s h sig)
            (error 'ssh-host-key-error :message "host-key signature verification failed"
                                       :fingerprint (host-key-fingerprint k-s)))
          (when host-key-verifier (funcall host-key-verifier k-s))
          (unless (ssh-conn-session-id conn) (setf (ssh-conn-session-id conn) h))
          (setf (ssh-conn-server-host-key conn) k-s)
          (let* ((sid (ssh-conn-session-id conn))
                 (km (mpint-bytes k))
                 (key-c2s (derive-key km h sid #\C 64))    ; encryption keys
                 (key-s2c (derive-key km h sid #\D 64)))
            (write-packet conn (make-array 1 :element-type '(unsigned-byte 8)
                                             :initial-element +msg-newkeys+))
            (setf (ssh-conn-send-cipher conn) (make-openssh-cipher key-c2s))
            (when strict (setf (ssh-conn-send-seq conn) 0))
            (expect-msg conn +msg-newkeys+ "NEWKEYS")
            (setf (ssh-conn-recv-cipher conn) (make-openssh-cipher key-s2c))
            (when strict (setf (ssh-conn-recv-seq conn) 0))
            h)))))))

;;; ---- base64 (no padding, for fingerprints) ---------------------------------
(defparameter +b64+ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
(defun base64-nopad (bytes)
  (let ((s (make-string-output-stream)) (nn (length bytes)))
    (loop for i from 0 below nn by 3 do
      (let* ((b0 (aref bytes i))
             (b1 (if (< (+ i 1) nn) (aref bytes (+ i 1)) 0))
             (b2 (if (< (+ i 2) nn) (aref bytes (+ i 2)) 0))
             (trip (logior (ash b0 16) (ash b1 8) b2))
             (k (- nn i)))
        (write-char (char +b64+ (ldb (byte 6 18) trip)) s)
        (write-char (char +b64+ (ldb (byte 6 12) trip)) s)
        (when (>= k 2) (write-char (char +b64+ (ldb (byte 6 6) trip)) s))
        (when (>= k 3) (write-char (char +b64+ (ldb (byte 6 0) trip)) s))))
    (get-output-stream-string s)))
