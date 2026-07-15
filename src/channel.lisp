;;;; channel.lisp — the connection layer (RFC 4254): a session channel + exec.

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

(defun exec-command (conn command)
  "Open a session channel, run COMMAND, and collect its output.  Returns
   (values STDOUT-BYTES STDERR-BYTES EXIT-STATUS)."
  (let ((local-id 0))
    ;; CHANNEL_OPEN "session"
    (let ((w (make-writer)))
      (w-byte w +msg-channel-open+)
      (w-string w "session")
      (w-u32 w local-id) (w-u32 w *initial-window*) (w-u32 w *max-packet*)
      (write-packet conn (writer-bytes w)))
    (let ((p (read-payload conn)))
      (unless (= (aref p 0) +msg-channel-open-confirmation+)
        (ssh-error "session channel open failed (message ~d)" (aref p 0)))
      (let* ((r (make-reader p 1))
             (remote-id (progn (r-u32 r) (r-u32 r))))     ; skip our id, take server's
        ;; CHANNEL_REQUEST "exec"
        (let ((w (make-writer)))
          (w-byte w +msg-channel-request+)
          (w-u32 w remote-id) (w-string w "exec") (w-bool w t) (w-string w command)
          (write-packet conn (writer-bytes w)))
        ;; pump until the channel closes
        (let ((out (make-array 256 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
              (err (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
              (exit nil) (window *initial-window*))
          (flet ((absorb (dst d) (loop for b across d do (vector-push-extend b dst))))
            (loop
              (let* ((p (read-payload conn)) (msg (aref p 0)) (r (make-reader p 1)))
                (cond
                  ((= msg +msg-channel-data+)
                   (r-u32 r)
                   (let ((d (r-string r)))
                     (absorb out d)
                     ;; replenish the flow-control window as we consume
                     (decf window (length d))
                     (when (< window (floor *initial-window* 2))
                       (let ((w (make-writer)))
                         (w-byte w +msg-channel-window-adjust+)
                         (w-u32 w remote-id) (w-u32 w *initial-window*)
                         (write-packet conn (writer-bytes w)))
                       (incf window *initial-window*))))
                  ((= msg +msg-channel-extended-data+)
                   (r-u32 r) (r-u32 r) (absorb err (r-string r)))
                  ((= msg +msg-channel-request+)
                   (r-u32 r)
                   (let ((req (r-cstring r)))
                     (r-bool r)
                     (when (string= req "exit-status") (setf exit (r-u32 r)))))
                  ((= msg +msg-channel-close+)
                   (let ((w (make-writer)))
                     (w-byte w +msg-channel-close+) (w-u32 w remote-id)
                     (write-packet conn (writer-bytes w)))
                   (return))
                  ((or (= msg +msg-channel-eof+)
                       (= msg +msg-channel-window-adjust+)
                       (= msg +msg-channel-success+)
                       (= msg +msg-channel-failure+))))))) ; ignore
          (values (coerce out '(simple-array (unsigned-byte 8) (*)))
                  (coerce err '(simple-array (unsigned-byte 8) (*)))
                  exit))))))
