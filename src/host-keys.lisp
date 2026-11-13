;;;; host-keys.lisp — known_hosts host-key verification.
;;;;
;;;; A host-key verifier is a function of one argument — the server's host-key
;;;; blob — called after its signature over the exchange hash has already checked
;;;; out.  It should signal to reject an untrusted host.  make-known-hosts-verifier
;;;; implements the usual OpenSSH policy: accept a matching known key, reject a
;;;; changed key (possible MITM), and trust-on-first-use an unknown host.

(in-package #:conch)

;;; ---- base64 (padded) -------------------------------------------------------
(defun base64-encode (bytes)
  (let ((s (make-string-output-stream)) (nn (length bytes)))
    (loop for i from 0 below nn by 3 do
      (let* ((b0 (aref bytes i))
             (b1 (if (< (+ i 1) nn) (aref bytes (+ i 1)) 0))
             (b2 (if (< (+ i 2) nn) (aref bytes (+ i 2)) 0))
             (trip (logior (ash b0 16) (ash b1 8) b2)) (k (- nn i)))
        (write-char (char +b64+ (ldb (byte 6 18) trip)) s)
        (write-char (char +b64+ (ldb (byte 6 12) trip)) s)
        (write-char (if (>= k 2) (char +b64+ (ldb (byte 6 6) trip)) #\=) s)
        (write-char (if (>= k 3) (char +b64+ (ldb (byte 6 0) trip)) #\=) s)))
    (get-output-stream-string s)))

;;; ---- small string helpers --------------------------------------------------
(defun split-ws (string)
  (let ((toks '()) (start nil))
    (dotimes (i (length string))
      (let ((ws (member (char string i) '(#\Space #\Tab))))
        (cond ((and (not ws) (null start)) (setf start i))
              ((and ws start) (push (subseq string start i) toks) (setf start nil)))))
    (when start (push (subseq string start) toks))
    (nreverse toks)))

(defun split-commas (string)
  (loop for start = 0 then (1+ pos)
        for pos = (position #\, string :start start)
        collect (subseq string start pos)
        while pos))

;;; ---- known_hosts -----------------------------------------------------------
(defun host-entry-name (host port)
  (if (= port 22) host (format nil "[~a]:~d" host port)))

(defun known-hosts-path ()
  (merge-pathnames ".ssh/known_hosts" (user-homedir-pathname)))

(defun known-hosts-check (path entry keytype b64)
  "Return (values KNOWN CORRECT): KNOWN if a line matches ENTRY + KEYTYPE;
   CORRECT if such a line also carries the given B64 key."
  (let ((known nil))
    (when (probe-file path)
      (with-open-file (s path :if-does-not-exist nil)
        (when s
          (loop for line = (read-line s nil nil) while line do
            (let ((line (string-trim '(#\Space #\Tab #\Return) line)))
              (unless (or (zerop (length line)) (char= (char line 0) #\#))
                (let ((toks (split-ws line)))
                  (when (and (>= (length toks) 3)
                             (member entry (split-commas (first toks)) :test #'string=)
                             (string= (second toks) keytype))
                    (setf known t)
                    (when (string= (third toks) b64)
                      (return-from known-hosts-check (values t t)))))))))))
    (values known nil)))

(defun known-hosts-append (path entry keytype b64)
  (ensure-directories-exist path)
  (with-open-file (s path :direction :output :if-exists :append :if-does-not-exist :create)
    (format s "~a ~a ~a~%" entry keytype b64)))

(defun make-known-hosts-verifier (host &key (port 22) (path (known-hosts-path)) (add t))
  "A host-key verifier that checks the server key against a known_hosts file.
   Rejects a changed key (SSH-HOST-KEY-ERROR); with ADD (default), trust-on-
   first-use appends an unknown host and warns."
  (lambda (k-s)
    (let* ((entry (host-entry-name host port))
           (keytype (r-cstring (make-reader k-s)))
           (b64 (base64-encode (to-u8v k-s))))
      (multiple-value-bind (known correct) (known-hosts-check path entry keytype b64)
        (cond
          (correct t)
          (known (error 'ssh-host-key-error
                        :message (format nil "HOST KEY CHANGED for ~a — possible man-in-the-middle" entry)
                        :fingerprint (host-key-fingerprint k-s) :key k-s :kind :changed))
          (add (known-hosts-append path entry keytype b64)
               (warn "conch: trusting new host ~a (~a); added to ~a"
                     entry (host-key-fingerprint k-s) path)
               t)
          (t (error 'ssh-host-key-error
                    :message (format nil "unknown host ~a" entry)
                    :fingerprint (host-key-fingerprint k-s) :key k-s :kind :unknown)))))))

(defun known-hosts-trust (host key-blob &key (port 22) (path (known-hosts-path)))
  "Record KEY-BLOB (an SSH-HOST-KEY-ERROR's SSH-HOST-KEY-BLOB) as HOST's key in PATH: what an app
   does once its user has accepted an unknown host's fingerprint.  The next connection checks
   against it."
  (known-hosts-append path (host-entry-name host port)
                      (r-cstring (make-reader key-blob)) (base64-encode (to-u8v key-blob)))
  t)
