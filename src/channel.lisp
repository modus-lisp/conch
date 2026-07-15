;;;; channel.lisp — the connection layer (RFC 4254): a bidirectional session
;;;; channel with flow control, plus exec-command built on top.

(in-package #:conch)

(defconstant +msg-channel-open+ 90)
(defconstant +msg-channel-open-confirmation+ 91)
(defconstant +msg-channel-open-failure+ 92)
(defconstant +msg-channel-window-adjust+ 93)
(defconstant +msg-channel-data+ 94)
(defconstant +msg-channel-extended-data+ 95)
(defconstant +msg-channel-eof+ 96)
(defconstant +msg-channel-close+ 97)
(defconstant +msg-channel-request+ 98)
(defconstant +msg-channel-success+ 99)
(defconstant +msg-channel-failure+ 100)

(defparameter *initial-window* (* 2 1024 1024))
(defparameter *max-packet* 32768)

(defstruct chan
  conn local-id remote-id
  (send-window 0) (recv-window 0) (send-max 32768)
  (in (make-array 4096 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  (in-pos 0)
  (err (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
  (eof nil) (closed nil) (close-sent nil) (exit nil))

(defun chan-avail (c) (- (fill-pointer (chan-in c)) (chan-in-pos c)))

;;; ---- packet dispatch -------------------------------------------------------
(defun chan-maybe-adjust-window (c)
  (when (< (chan-recv-window c) (floor *initial-window* 2))
    (let ((inc (- *initial-window* (chan-recv-window c))) (w (make-writer)))
      (w-byte w +msg-channel-window-adjust+) (w-u32 w (chan-remote-id c)) (w-u32 w inc)
      (write-packet (chan-conn c) (writer-bytes w))
      (incf (chan-recv-window c) inc))))

(defun chan-process (c p)
  (let ((msg (aref p 0)) (r (make-reader p 1)))
    (cond
      ((= msg +msg-channel-data+)
       (r-u32 r)
       (let ((d (r-string r)))
         (loop for b across d do (vector-push-extend b (chan-in c)))
         (decf (chan-recv-window c) (length d))
         (chan-maybe-adjust-window c)))
      ((= msg +msg-channel-extended-data+)
       (r-u32 r) (r-u32 r)
       (loop for b across (r-string r) do (vector-push-extend b (chan-err c))))
      ((= msg +msg-channel-window-adjust+)
       (r-u32 r) (incf (chan-send-window c) (r-u32 r)))
      ((= msg +msg-channel-eof+) (setf (chan-eof c) t))
      ((= msg +msg-channel-close+) (setf (chan-closed c) t (chan-eof c) t))
      ((= msg +msg-channel-request+)
       (r-u32 r)
       (let ((req (r-cstring r)))
         (r-bool r)
         (when (string= req "exit-status") (setf (chan-exit c) (r-u32 r)))))
      (t nil))))                          ; success/failure/other: ignore here

(defun chan-pump (c) (chan-process c (read-payload (chan-conn c))))

;;; ---- open / exec -----------------------------------------------------------
(defun open-session (conn)
  (let ((w (make-writer)))
    (w-byte w +msg-channel-open+) (w-string w "session")
    (w-u32 w 0) (w-u32 w *initial-window*) (w-u32 w *max-packet*)
    (write-packet conn (writer-bytes w)))
  (let ((p (read-payload conn)))
    (unless (= (aref p 0) +msg-channel-open-confirmation+)
      (ssh-error "session channel open failed (message ~d)" (aref p 0)))
    (let ((r (make-reader p 1)))
      (r-u32 r)                                    ; our id (0)
      (let ((remote (r-u32 r)) (swin (r-u32 r)) (smax (r-u32 r)))
        (make-chan :conn conn :local-id 0 :remote-id remote
                   :send-window swin :recv-window *initial-window* :send-max smax)))))

(defun chan-exec (c command)
  (let ((w (make-writer)))
    (w-byte w +msg-channel-request+) (w-u32 w (chan-remote-id c))
    (w-string w "exec") (w-bool w t) (w-string w command)
    (write-packet (chan-conn c) (writer-bytes w)))
  (loop for p = (read-payload (chan-conn c)) for msg = (aref p 0)
        do (cond ((= msg +msg-channel-success+) (return t))
                 ((= msg +msg-channel-failure+) (ssh-error "exec request refused by server"))
                 (t (chan-process c p)))))

;;; ---- read / write ----------------------------------------------------------
(defun chan-read-exact (c n)
  "Read exactly N bytes of channel data (blocking); error on premature EOF."
  (loop while (< (chan-avail c) n)
        do (if (or (chan-eof c) (chan-closed c))
               (ssh-error "channel: unexpected EOF (have ~d, need ~d)" (chan-avail c) n)
               (chan-pump c)))
  (let ((start (chan-in-pos c)))
    (setf (chan-in-pos c) (+ start n))
    (coerce (subseq (chan-in c) start (+ start n)) '(simple-array (unsigned-byte 8) (*)))))

(defun chan-read-byte (c) (aref (chan-read-exact c 1) 0))

(defun chan-read-line (c)
  "Read up to and including a newline; return the line as a string without it."
  (let ((acc (make-array 32 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for b = (chan-read-byte c) until (= b 10) do (vector-push-extend b acc))
    (utf8->string (coerce acc '(simple-array (unsigned-byte 8) (*))))))

(defun chan-write (c bytes)
  (let ((bytes (to-u8v bytes)) (pos 0))
    (loop while (< pos (length bytes)) do
      (loop while (<= (chan-send-window c) 0) do (chan-pump c))   ; await WINDOW_ADJUST
      (let* ((chunk (min (- (length bytes) pos) (chan-send-window c) (chan-send-max c)))
             (w (make-writer)))
        (w-byte w +msg-channel-data+) (w-u32 w (chan-remote-id c))
        (w-string w (subseq bytes pos (+ pos chunk)))
        (write-packet (chan-conn c) (writer-bytes w))
        (decf (chan-send-window c) chunk) (incf pos chunk)))))

(defun chan-send-eof (c)
  (let ((w (make-writer)))
    (w-byte w +msg-channel-eof+) (w-u32 w (chan-remote-id c))
    (write-packet (chan-conn c) (writer-bytes w))))

(defun chan-close (c)
  (unless (chan-close-sent c)
    (let ((w (make-writer)))
      (w-byte w +msg-channel-close+) (w-u32 w (chan-remote-id c))
      (write-packet (chan-conn c) (writer-bytes w)))
    (setf (chan-close-sent c) t))
  (loop until (chan-closed c) do (chan-pump c)))

;;; ---- exec-command (collect all output) -------------------------------------
(defun exec-command (conn command)
  "Open a session channel, run COMMAND, collect its output.  Returns
   (values STDOUT-BYTES STDERR-BYTES EXIT-STATUS)."
  (let ((c (open-session conn)))
    (chan-exec c command)
    (loop until (chan-closed c) do (chan-pump c))
    (chan-close c)
    (values (coerce (subseq (chan-in c) (chan-in-pos c)) '(simple-array (unsigned-byte 8) (*)))
            (coerce (chan-err c) '(simple-array (unsigned-byte 8) (*)))
            (chan-exit c))))
