;;;; sftp.lisp — SFTP client (SSH File Transfer Protocol, version 3).
;;;;
;;;; draft-ietf-secsh-filexfer-02 (what OpenSSH speaks).  SFTP runs over an
;;;; "sftp" subsystem channel: a simple request/response protocol of
;;;; length-prefixed packets (uint32 length, byte type, uint32 request-id, …).
;;;; conch does synchronous request/response — one outstanding request at a time.

(in-package #:conch)

;; packet types
(defconstant +fxp-init+ 1)      (defconstant +fxp-version+ 2)
(defconstant +fxp-open+ 3)      (defconstant +fxp-close+ 4)
(defconstant +fxp-read+ 5)      (defconstant +fxp-write+ 6)
(defconstant +fxp-lstat+ 7)     (defconstant +fxp-fstat+ 8)
(defconstant +fxp-opendir+ 11)  (defconstant +fxp-readdir+ 12)
(defconstant +fxp-remove+ 13)   (defconstant +fxp-mkdir+ 14)
(defconstant +fxp-rmdir+ 15)    (defconstant +fxp-realpath+ 16)
(defconstant +fxp-stat+ 17)     (defconstant +fxp-rename+ 18)
(defconstant +fxp-status+ 101)  (defconstant +fxp-handle+ 102)
(defconstant +fxp-data+ 103)    (defconstant +fxp-name+ 104)
(defconstant +fxp-attrs+ 105)
;; open flags
(defconstant +fxf-read+ 1)   (defconstant +fxf-write+ 2)  (defconstant +fxf-append+ 4)
(defconstant +fxf-creat+ 8)  (defconstant +fxf-trunc+ 16) (defconstant +fxf-excl+ 32)
;; status codes
(defconstant +fx-ok+ 0) (defconstant +fx-eof+ 1)
(defconstant +fx-no-such-file+ 2) (defconstant +fx-permission-denied+ 3)

(defparameter *sftp-chunk* 32768)

(defstruct sftp chan (idc 0) version)

(defun sftp-next-id (s) (setf (sftp-idc s) (logand (1+ (sftp-idc s)) #xffffffff)))

;;; ---- framing ---------------------------------------------------------------
(defun sftp-send (s type payload)
  (let ((w (make-writer)))
    (w-u32 w (+ 1 (length payload)))
    (w-byte w type) (w-raw w payload)
    (chan-write (sftp-chan s) (writer-bytes w))))

(defun sftp-recv (s)
  "Read one SFTP packet; return (values TYPE reader-over-payload)."
  (let* ((len (be->integer (chan-read-exact (sftp-chan s) 4)))
         (data (chan-read-exact (sftp-chan s) len)))
    (values (aref data 0) (make-reader data 1))))

(defun skip-attrs (r)
  "Consume an ATTRS structure and discard it."
  (let ((flags (r-u32 r)))
    (when (logtest flags 1) (r-u64 r))            ; size
    (when (logtest flags 2) (r-u32 r) (r-u32 r))  ; uid gid
    (when (logtest flags 4) (r-u32 r))            ; permissions
    (when (logtest flags 8) (r-u32 r) (r-u32 r))  ; atime mtime
    (when (logtest flags #x80000000)
      (dotimes (i (r-u32 r)) (r-string r) (r-string r)))))

(defun sftp-fail (r what)
  (r-u32 r)                                        ; id
  (let ((code (r-u32 r)) (msg (r-cstring r)))
    (ssh-error "sftp ~a failed (code ~d): ~a" what code msg)))

;;; ---- session ---------------------------------------------------------------
(defun sftp-open-session (conn)
  "Open an SFTP session over CONN (subsystem channel + INIT/VERSION handshake)."
  (let ((c (open-session conn)))
    (chan-subsystem c "sftp")
    (let ((s (make-sftp :chan c)))
      (let ((w (make-writer))) (w-u32 w 3) (sftp-send s +fxp-init+ (writer-bytes w)))
      (multiple-value-bind (type r) (sftp-recv s)
        (unless (= type +fxp-version+) (ssh-error "sftp: expected VERSION, got ~d" type))
        (setf (sftp-version s) (r-u32 r)))
      s)))

;;; ---- primitives ------------------------------------------------------------
(defun sftp-get-handle (s what)
  (multiple-value-bind (type r) (sftp-recv s)
    (cond ((= type +fxp-handle+) (r-u32 r) (r-string r))
          ((= type +fxp-status+) (sftp-fail r what))
          (t (ssh-error "sftp: expected HANDLE, got ~d" type)))))

(defun sftp-expect-ok (s id what)
  (declare (ignore id))
  (multiple-value-bind (type r) (sftp-recv s)
    (unless (= type +fxp-status+) (ssh-error "sftp: expected STATUS, got ~d" type))
    (r-u32 r)
    (let ((code (r-u32 r)))
      (unless (= code +fx-ok+) (ssh-error "sftp ~a failed (code ~d): ~a" what code (r-cstring r)))
      t)))

(defun sftp-open-file (s path flags &optional mode)
  (let ((id (sftp-next-id s)) (w (make-writer)))
    (w-u32 w id) (w-string w path) (w-u32 w flags)
    (if mode (progn (w-u32 w 4) (w-u32 w mode)) (w-u32 w 0))   ; ATTRS
    (sftp-send s +fxp-open+ (writer-bytes w))
    (sftp-get-handle s "open")))

(defun sftp-close (s handle)
  (let ((id (sftp-next-id s)) (w (make-writer)))
    (w-u32 w id) (w-string w handle)
    (sftp-send s +fxp-close+ (writer-bytes w))
    (sftp-expect-ok s id "close")))

(defun sftp-read-chunk (s handle offset length)
  "Return up to LENGTH bytes at OFFSET, or NIL at EOF."
  (let ((id (sftp-next-id s)) (w (make-writer)))
    (w-u32 w id) (w-string w handle) (w-u64 w offset) (w-u32 w length)
    (sftp-send s +fxp-read+ (writer-bytes w))
    (multiple-value-bind (type r) (sftp-recv s)
      (cond ((= type +fxp-data+) (r-u32 r) (r-string r))
            ((= type +fxp-status+) (r-u32 r)
             (let ((code (r-u32 r)))
               (if (= code +fx-eof+) nil (ssh-error "sftp read failed (code ~d): ~a" code (r-cstring r)))))
            (t (ssh-error "sftp: expected DATA/STATUS, got ~d" type))))))

(defun sftp-write-chunk (s handle offset data)
  (let ((id (sftp-next-id s)) (w (make-writer)))
    (w-u32 w id) (w-string w handle) (w-u64 w offset) (w-string w data)
    (sftp-send s +fxp-write+ (writer-bytes w))
    (sftp-expect-ok s id "write")))

;;; ---- high-level operations -------------------------------------------------
(defun sftp-get (s remote-path local-path)
  "Download REMOTE-PATH to LOCAL-PATH.  Returns bytes transferred."
  (let ((handle (sftp-open-file s remote-path +fxf-read+))
        (out (make-array 4096 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
        (off 0))
    (unwind-protect
         (loop for data = (sftp-read-chunk s handle off *sftp-chunk*)
               while data
               do (loop for b across data do (vector-push-extend b out))
                  (incf off (length data)))
      (sftp-close s handle))
    (%write-file-bytes local-path (coerce out '(simple-array (unsigned-byte 8) (*))))))

(defun sftp-put (s local-path remote-path)
  "Upload LOCAL-PATH to REMOTE-PATH.  Returns bytes transferred."
  (let* ((data (%file-bytes local-path))
         (len (length data))
         (handle (sftp-open-file s remote-path
                                 (logior +fxf-write+ +fxf-creat+ +fxf-trunc+) #o644))
         (off 0))
    (unwind-protect
         (loop while (< off len)
               for n = (min *sftp-chunk* (- len off))
               do (sftp-write-chunk s handle off (subseq data off (+ off n)))
                  (incf off n))
      (sftp-close s handle))
    len))

(defun sftp-ls (s path)
  "List directory PATH; return a list of entry name strings."
  (let ((handle (sftp-opendir s path)) (names '()))
    (unwind-protect
         (loop for batch = (sftp-readdir s handle)
               while batch do (setf names (nconc names batch)))
      (sftp-close s handle))
    names))

(defun sftp-opendir (s path)
  (let ((id (sftp-next-id s)) (w (make-writer)))
    (w-u32 w id) (w-string w path)
    (sftp-send s +fxp-opendir+ (writer-bytes w))
    (sftp-get-handle s "opendir")))

(defun sftp-readdir (s handle)
  "Return a batch of filename strings, or NIL at end-of-directory."
  (let ((id (sftp-next-id s)) (w (make-writer)))
    (w-u32 w id) (w-string w handle)
    (sftp-send s +fxp-readdir+ (writer-bytes w))
    (multiple-value-bind (type r) (sftp-recv s)
      (cond ((= type +fxp-name+)
             (r-u32 r)
             (let ((count (r-u32 r)) (names '()))
               (dotimes (i count) (push (r-cstring r) names) (r-cstring r) (skip-attrs r))
               (nreverse names)))
            ((= type +fxp-status+) (r-u32 r)
             (let ((code (r-u32 r)))
               (if (= code +fx-eof+) nil (ssh-error "sftp readdir failed (code ~d)" code))))
            (t (ssh-error "sftp: expected NAME/STATUS, got ~d" type))))))

(defun sftp-realpath (s path)
  "Canonicalize PATH on the server; return the absolute path string."
  (let ((id (sftp-next-id s)) (w (make-writer)))
    (w-u32 w id) (w-string w path)
    (sftp-send s +fxp-realpath+ (writer-bytes w))
    (multiple-value-bind (type r) (sftp-recv s)
      (cond ((= type +fxp-name+) (r-u32 r) (r-u32 r) (r-cstring r))
            ((= type +fxp-status+) (sftp-fail r "realpath"))
            (t (ssh-error "sftp: expected NAME, got ~d" type))))))

(defun sftp-mkdir (s path)
  (let ((id (sftp-next-id s)) (w (make-writer)))
    (w-u32 w id) (w-string w path) (w-u32 w 0)
    (sftp-send s +fxp-mkdir+ (writer-bytes w))
    (sftp-expect-ok s id "mkdir")))

(defun sftp-rmdir (s path)
  (let ((id (sftp-next-id s)) (w (make-writer)))
    (w-u32 w id) (w-string w path)
    (sftp-send s +fxp-rmdir+ (writer-bytes w))
    (sftp-expect-ok s id "rmdir")))

(defun sftp-remove (s path)
  (let ((id (sftp-next-id s)) (w (make-writer)))
    (w-u32 w id) (w-string w path)
    (sftp-send s +fxp-remove+ (writer-bytes w))
    (sftp-expect-ok s id "remove")))
