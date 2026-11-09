;;;; client.lisp — private-key loading + the high-level client API.

(in-package #:conch)

;;; ---- base64 decode ---------------------------------------------------------
(defun base64-decode (string)
  "Decode standard base64 (ignoring whitespace and '=' padding) to bytes."
  (let ((vals (make-array 128 :initial-element -1))
        (out (make-array 48 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
        (acc 0) (bits 0))
    (dotimes (i 64) (setf (aref vals (char-code (char +b64+ i))) i))
    (loop for ch across string
          for v = (if (< (char-code ch) 128) (aref vals (char-code ch)) -1)
          when (>= v 0) do
            (setf acc (logior (ash acc 6) v) bits (+ bits 6))
            (when (>= bits 8)
              (decf bits 8)
              (vector-push-extend (logand (ash acc (- bits)) #xff) out)))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun read-file-string (path)
  (with-open-file (s path :element-type 'character)
    (let ((str (make-string (file-length s))))
      (subseq str 0 (read-sequence str s)))))

(defun extract-pem (text label)
  (let* ((begin (format nil "-----BEGIN ~a-----" label))
         (end (format nil "-----END ~a-----" label))
         (b (search begin text)))
    (unless b (ssh-error "no ~a block in key file" label))
    (let ((e (search end text :start2 (+ b (length begin)))))
      (remove-if (lambda (c) (member c '(#\Newline #\Return #\Space #\Tab)))
                 (subseq text (+ b (length begin)) e)))))

;;; ---- OpenSSH private key (openssh-key-v1) ----------------------------------
(defun load-private-key (path)
  "Load an *unencrypted* OpenSSH Ed25519 private key.  Returns
   (values SECRET-32 PUBLIC-32 COMMENT)."
  (let* ((blob (base64-decode (extract-pem (read-file-string path) "OPENSSH PRIVATE KEY")))
         (r (make-reader blob)))
    (unless (equalp (r-raw r 15) (to-u8v (format nil "openssh-key-v1~c" #\Nul)))
      (ssh-error "not an openssh-key-v1 private key"))
    (let ((cipher (r-cstring r)) (kdf (r-cstring r)))
      (r-string r)                                  ; kdfoptions
      (unless (and (string= cipher "none") (string= kdf "none"))
        (ssh-error "encrypted private keys are not yet supported (cipher ~a)" cipher))
      (unless (= (r-u32 r) 1) (ssh-error "expected exactly one key in the file"))
      (r-string r)                                  ; public key blob (redundant)
      (let ((pr (make-reader (r-string r))))        ; private section (plaintext)
        (unless (= (r-u32 pr) (r-u32 pr))
          (ssh-error "private-key checkint mismatch"))
        (let ((keytype (r-cstring pr)))
          (unless (string= keytype "ssh-ed25519")
            (ssh-error "unsupported key type ~a (only ssh-ed25519)" keytype))
          (let* ((pub (r-string pr))                ; 32-byte public key
                 (sk64 (r-string pr))               ; 64 bytes: seed32 ‖ pub32
                 (comment (r-cstring pr)))
            (values (subseq sk64 0 32) pub comment)))))))

;;; ---- high-level API --------------------------------------------------------
(defun default-user ()
  (or (sb-ext:posix-getenv "USER") (sb-ext:posix-getenv "LOGNAME") "root"))

(defun connect (host &key (port 22) (user (default-user)) identity host-key-verifier
                          (known-hosts t))
  "Open an authenticated SSH connection to HOST and return the live SSH-CONN.
   IDENTITY is the path to an OpenSSH Ed25519 private key.  HOST-KEY-VERIFIER
   overrides the default, which — when KNOWN-HOSTS is true — checks the server
   against ~/.ssh/known_hosts (trust-on-first-use)."
  (multiple-value-bind (sock stream) (tcp-connect host port)
    (let ((conn (make-ssh-conn :socket sock :stream stream)) (ok nil))
      (unwind-protect
           (progn
             (exchange-versions conn)
             (do-kex conn :host-key-verifier
                     (or host-key-verifier
                         (and known-hosts (make-known-hosts-verifier host :port port))))
             (request-service conn "ssh-userauth")
             (unless identity (ssh-error "no identity key supplied"))
             ;; IDENTITY is a path, or (SECRET-32 PUBLIC-32) already in hand (a key kept in
             ;; the device's keychain, which never goes to a file)
             (multiple-value-bind (secret pub)
                 (if (consp identity)
                     (values (first identity) (second identity))
                     (load-private-key identity))
               (userauth-publickey conn user secret pub))
             (setf ok t)
             conn)
        (unless ok (ignore-errors (sb-bsd-sockets:socket-close (ssh-conn-socket conn))))))))

(defun disconnect (conn)
  (ignore-errors
   (let ((w (make-writer)))
     (w-byte w +msg-disconnect+) (w-u32 w 11) (w-string w "bye") (w-string w "")
     (write-packet conn (writer-bytes w))))
  (ignore-errors (sb-bsd-sockets:socket-close (ssh-conn-socket conn))))

(defmacro with-connection ((var host &rest args) &body body)
  `(let ((,var (connect ,host ,@args)))
     (unwind-protect (progn ,@body) (disconnect ,var))))

(defun run (host command &key (port 22) (user (default-user)) identity host-key-verifier)
  "Connect to HOST, authenticate, run COMMAND, and return
   (values STDOUT-STRING EXIT-STATUS STDERR-STRING)."
  (with-connection (conn host :port port :user user :identity identity
                              :host-key-verifier host-key-verifier)
    (multiple-value-bind (out err status) (exec-command conn command)
      (values (utf8->string out) status (utf8->string err)))))

(defun upload (host local-path remote-path
               &key (port 22) (user (default-user)) identity host-key-verifier)
  "Copy the local file LOCAL-PATH to REMOTE-PATH on HOST via scp.  Returns bytes sent."
  (with-connection (conn host :port port :user user :identity identity
                              :host-key-verifier host-key-verifier)
    (scp-upload conn local-path remote-path)))

(defun download (host remote-path local-path
                 &key (port 22) (user (default-user)) identity host-key-verifier)
  "Copy REMOTE-PATH on HOST into the local file LOCAL-PATH via scp.  Returns bytes."
  (with-connection (conn host :port port :user user :identity identity
                              :host-key-verifier host-key-verifier)
    (scp-download conn remote-path local-path)))

;;; ---- SFTP ------------------------------------------------------------------
(defmacro with-sftp ((var host &rest connect-args) &body body)
  "Connect to HOST, open an SFTP session bound to VAR, run BODY, and tear down."
  (let ((conn (gensym)))
    `(with-connection (,conn ,host ,@connect-args)
       (let ((,var (sftp-open-session ,conn)))
         ,@body))))

(defun sftp-download (host remote local
                      &key (port 22) (user (default-user)) identity host-key-verifier)
  "Download REMOTE from HOST to LOCAL via SFTP.  Returns bytes."
  (with-sftp (s host :port port :user user :identity identity :host-key-verifier host-key-verifier)
    (sftp-get s remote local)))

(defun sftp-upload (host local remote
                    &key (port 22) (user (default-user)) identity host-key-verifier)
  "Upload LOCAL to REMOTE on HOST via SFTP.  Returns bytes."
  (with-sftp (s host :port port :user user :identity identity :host-key-verifier host-key-verifier)
    (sftp-put s local remote)))

(defun sftp-list (host path
                  &key (port 22) (user (default-user)) identity host-key-verifier)
  "List directory PATH on HOST via SFTP.  Returns entry names."
  (with-sftp (s host :port port :user user :identity identity :host-key-verifier host-key-verifier)
    (sftp-ls s path)))
