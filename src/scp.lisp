;;;; scp.lisp — file transfer via the classic scp protocol (rcp-over-SSH).
;;;;
;;;; conch execs the remote `scp` in sink (-t, we send) or source (-f, we
;;;; receive) mode and speaks the line/ack protocol over the channel: a control
;;;; message "C<mode> <size> <name>\n", the raw file bytes, and \0 status bytes
;;;; (0 ok, 1 warning, 2 error) flowing back.  Single regular files; directories
;;;; and timestamp preservation are not yet handled.

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

(defun scp-send-ack (c)
  (chan-write c (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun scp-read-ack (c)
  "Read an scp status byte: 0 ok, 1 warning (message follows), 2 error."
  (let ((b (chan-read-byte c)))
    (cond ((= b 0) t)
          ((= b 1) (warn "scp: ~a" (chan-read-line c)) t)
          ((= b 2) (ssh-error "scp (remote): ~a" (chan-read-line c)))
          (t (ssh-error "scp: unexpected status byte ~d" b)))))

(defun scp-upload (conn local-path remote-path)
  "Upload LOCAL-PATH to REMOTE-PATH on the already-connected CONN.  Returns the
   number of bytes sent."
  (let* ((data (%file-bytes local-path))
         (size (length data))
         (name (file-namestring local-path))
         (c (open-session conn)))
    (chan-exec c (format nil "scp -t ~a" (shell-quote remote-path)))
    (scp-read-ack c)                              ; sink ready
    (chan-write c (string->utf8 (format nil "C0644 ~d ~a~c" size name #\Newline)))
    (scp-read-ack c)                              ; header accepted
    (chan-write c data)
    (scp-send-ack c)                              ; \0 = end of this file
    (scp-read-ack c)                              ; stored ok
    (chan-send-eof c)
    (chan-close c)
    size))

(defun scp-download (conn remote-path local-path)
  "Download REMOTE-PATH from CONN into LOCAL-PATH.  Returns (values BYTES NAME)."
  (let ((c (open-session conn)))
    (chan-exec c (format nil "scp -f ~a" (shell-quote remote-path)))
    (scp-send-ack c)                              ; tell the source we are ready
    (let ((b (chan-read-byte c)))
      (cond ((= b 1) (warn "scp: ~a" (chan-read-line c)))
            ((= b 2) (ssh-error "scp (remote): ~a" (chan-read-line c)))
            ((/= b (char-code #\C))
             (ssh-error "scp: expected a file (C) message, got byte ~d" b)))
      ;; parse "C<mode> <size> <name>" (leading C already consumed)
      (let* ((line (chan-read-line c))
             (sp1 (position #\Space line))
             (sp2 (position #\Space line :start (1+ sp1)))
             (size (parse-integer line :start (1+ sp1) :end sp2))
             (name (subseq line (1+ sp2))))
        (scp-send-ack c)                          ; ready for the bytes
        (let ((data (chan-read-exact c size)))
          (let ((trailer (chan-read-byte c)))     ; source's end-of-file \0
            (unless (= trailer 0)
              (ssh-error "scp: bad end-of-file byte ~d" trailer)))
          (scp-send-ack c)                        ; we received it ok
          (%write-file-bytes local-path data)
          (chan-close c)
          (values size name))))))
