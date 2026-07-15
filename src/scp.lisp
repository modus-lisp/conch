;;;; scp.lisp — file transfer via the classic scp protocol (rcp-over-SSH).
;;;;
;;;; conch execs the remote `scp` in sink (-t, we send) or source (-f, we
;;;; receive) mode and speaks the line/ack protocol over the channel: control
;;;; messages "C<mode> <size> <name>\n" (a file), "D<mode> 0 <name>\n" / "E\n"
;;;; (enter/leave a directory, for -r), the raw file bytes, and \0 status bytes
;;;; (0 ok, 1 warning, 2 error) flowing back.  Regular files and directory trees.

(in-package #:conch)

(defun %file-bytes (path)
  (with-open-file (s path :element-type '(unsigned-byte 8))
    (let ((buf (make-array (file-length s) :element-type '(unsigned-byte 8))))
      (read-sequence buf s)
      buf)))

(defun %write-file-bytes (path bytes)
  (with-open-file (s path :element-type '(unsigned-byte 8) :direction :output
                          :if-exists :supersede :if-does-not-exist :create)
    (write-sequence bytes s))
  (length bytes))

(defun shell-quote (s)
  "Single-quote S for a POSIX shell (the remote runs the command via /bin/sh)."
  (with-output-to-string (o)
    (write-char #\' o)
    (loop for ch across s do
      (if (char= ch #\') (write-string "'\\''" o) (write-char ch o)))
    (write-char #\' o)))

(defun path-basename (p)
  "Final path component of P (string or pathname)."
  (let* ((s (string-right-trim "/" (namestring p)))
         (slash (position #\/ s :from-end t)))
    (if slash (subseq s (1+ slash)) s)))

(defun path-join (dir name) (format nil "~a/~a" (string-right-trim "/" dir) name))

;;; ---- status bytes ----------------------------------------------------------
(defun scp-send-ack (c)
  (chan-write c (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun scp-read-ack (c)
  "Read an scp status byte: 0 ok, 1 warning (message follows), 2 error."
  (let ((b (chan-read-byte c)))
    (cond ((= b 0) t)
          ((= b 1) (warn "scp: ~a" (chan-read-line c)) t)
          ((= b 2) (ssh-error "scp (remote): ~a" (chan-read-line c)))
          (t (ssh-error "scp: unexpected status byte ~d" b)))))

(defun scp-parse-header (line)
  "Parse the tail of a C/D message ('<mode> <size> <name>').  → (values size name)."
  (let* ((sp1 (position #\Space line))
         (sp2 (position #\Space line :start (1+ sp1))))
    (values (parse-integer line :start (1+ sp1) :end sp2) (subseq line (1+ sp2)))))

;;; ---- upload (sink protocol) ------------------------------------------------
(defun scp-upload (conn local-path remote-path)
  "Upload LOCAL-PATH to REMOTE-PATH.  A directory is copied recursively.  Returns
   the number of file bytes sent."
  (if (uiop:directory-exists-p local-path)
      (let ((c (open-session conn)) (count 0))
        (chan-exec c (format nil "scp -rt ~a" (shell-quote remote-path)))
        (scp-read-ack c)
        (setf count (scp-send-tree c local-path))
        (chan-send-eof c) (chan-close c)
        count)
      (let ((c (open-session conn)) (n 0))
        (chan-exec c (format nil "scp -t ~a" (shell-quote remote-path)))
        (scp-read-ack c)
        (setf n (scp-send-file c local-path (file-namestring local-path)))
        (chan-send-eof c) (chan-close c)
        n)))

(defun scp-send-file (c local-path name)
  (let* ((data (%file-bytes local-path)) (size (length data)))
    (chan-write c (string->utf8 (format nil "C0644 ~d ~a~%" size name)))
    (scp-read-ack c)
    (chan-write c data)
    (scp-send-ack c)                              ; \0 ends the file
    (scp-read-ack c)
    size))

(defun scp-send-tree (c dir)
  "Recursively send DIR as D … (files) … E.  Returns total file bytes."
  (let ((dir (uiop:ensure-directory-pathname dir)))   ; trailing slash → real dir listing
    (chan-write c (string->utf8 (format nil "D0755 0 ~a~%" (path-basename dir))))
    (scp-read-ack c)
    (let ((count 0))
      (dolist (f (uiop:directory-files dir))
        (incf count (scp-send-file c f (file-namestring f))))
      (dolist (sub (uiop:subdirectories dir))
        (incf count (scp-send-tree c sub)))
      (chan-write c (string->utf8 (format nil "E~%")))
      (scp-read-ack c)
      count)))

;;; ---- download (source protocol) --------------------------------------------
(defun scp-download (conn remote-path local-path)
  "Download REMOTE-PATH into LOCAL-PATH.  A single file is written to LOCAL-PATH;
   a directory tree is created under LOCAL-PATH (treated as the parent).  Returns
   the number of file bytes received."
  (let ((c (open-session conn)))
    (chan-exec c (format nil "scp -rf ~a" (shell-quote remote-path)))
    (scp-send-ack c)                              ; we are ready
    (unwind-protect
         (let ((b (chan-read-byte c)))
           (case (code-char b)
             (#\C (multiple-value-bind (size name) (scp-parse-header (chan-read-line c))
                    (declare (ignore name))
                    (scp-recv-bytes c size local-path)))
             (#\D (scp-recv-tree c (chan-read-line c) local-path))
             (t (cond ((= b 1) (warn "scp: ~a" (chan-read-line c)) 0)
                      ((= b 2) (ssh-error "scp (remote): ~a" (chan-read-line c)))
                      (t (ssh-error "scp: unexpected byte ~d" b))))))
      (chan-close c))))

(defun scp-recv-bytes (c size dest)
  "Receive SIZE bytes (the C header already consumed) and write them to DEST."
  (scp-send-ack c)                                ; ready for bytes
  (let ((data (chan-read-exact c size)))
    (let ((trailer (chan-read-byte c)))
      (unless (= trailer 0) (ssh-error "scp: bad end-of-file byte ~d" trailer)))
    (scp-send-ack c)
    (%write-file-bytes dest data)))

(defun scp-recv-tree (c dline parent)
  "Handle a directory: DLINE is the D header tail; create PARENT/name and recurse
   until the matching E.  Returns file bytes received."
  (multiple-value-bind (size name) (scp-parse-header dline)
    (declare (ignore size))
    (let ((dir (path-join parent name)) (count 0))
      (ensure-directories-exist (pathname (concatenate 'string dir "/")))
      (scp-send-ack c)                            ; ack the D
      (loop
        (let ((b (chan-read-byte c)))
          (case (code-char b)
            (#\C (multiple-value-bind (fsize fname) (scp-parse-header (chan-read-line c))
                   (incf count (scp-recv-bytes c fsize (path-join dir fname)))))
            (#\D (incf count (scp-recv-tree c (chan-read-line c) dir)))
            (#\E (chan-read-line c) (scp-send-ack c) (return count))   ; consume the "E\n"
            (t (cond ((= b 1) (warn "scp: ~a" (chan-read-line c)))
                     ((= b 2) (ssh-error "scp (remote): ~a" (chan-read-line c)))
                     (t (ssh-error "scp: unexpected byte ~d in directory" b))))))))))
