;;;; buffer.lisp — SSH binary wire codec (RFC 4251 §5).
;;;;
;;;; SSH packets are built from a small set of typed fields: byte, boolean,
;;;; uint32/uint64 (big-endian), string (uint32 length prefix + bytes), mpint
;;;; (length-prefixed big-endian two's-complement), and name-list (a string of
;;;; comma-separated ASCII names).  A WRITER accumulates bytes; a READER walks a
;;;; byte vector.

(in-package #:conch)

(deftype u8v () '(simple-array (unsigned-byte 8) (*)))

(declaim (inline string->utf8 utf8->string))
(defun string->utf8 (s) (sb-ext:string-to-octets s :external-format :utf-8))
(defun utf8->string (bytes) (sb-ext:octets-to-string bytes :external-format :utf-8))

(defun to-u8v (x)
  "Coerce X (vector/string) to a simple (unsigned-byte 8) vector."
  (etypecase x
    (string (string->utf8 x))
    (vector (coerce x '(simple-array (unsigned-byte 8) (*))))))

;;; ---- writer ----------------------------------------------------------------
;;; A simple byte vector and a fill position, grown by doubling, and bytes copied in with REPLACE: an upload's
;;; every 32 KB chunk passes through a writer three times (the SFTP write, the channel's data, the packet), and
;;; a byte at a time through VECTOR-PUSH-EXTEND on an adjustable array was a third of an upload's time on modus.
(defstruct (writer (:constructor make-writer ()))
  (buf (make-array 64 :element-type '(unsigned-byte 8)) :type u8v)
  (fill 0 :type fixnum))

(defun w-room (w n)
  "Room in W for N more bytes; returns the position they go at."
  (let* ((at (writer-fill w)) (need (+ at n)) (buf (writer-buf w)))
    (when (> need (length buf))
      (let ((new (make-array (max need (* 2 (length buf))) :element-type '(unsigned-byte 8))))
        (replace new buf :end2 at)
        (setf (writer-buf w) new)))
    (setf (writer-fill w) need)
    at))

(defun writer-bytes (w)
  "The accumulated content as a fresh simple (unsigned-byte 8) vector."
  (subseq (writer-buf w) 0 (writer-fill w)))

(defun w-byte (w b) (let ((at (w-room w 1))) (setf (aref (writer-buf w) at) (logand b #xff))) w)

(defun w-raw (w bytes)
  (let* ((b (to-u8v bytes)) (at (w-room w (length b))))   ; room first: it may replace the buffer
    (replace (writer-buf w) b :start1 at))
  w)

(defun w-u32 (w n)
  (let ((at (w-room w 4)) (buf (writer-buf w)))
    (dotimes (i 4 w) (setf (aref buf (+ at i)) (logand (ash n (* -8 (- 3 i))) #xff)))))

(defun w-u64 (w n)
  (let ((at (w-room w 8)) (buf (writer-buf w)))
    (dotimes (i 8 w) (setf (aref buf (+ at i)) (logand (ash n (* -8 (- 7 i))) #xff)))))

(defun w-bool (w x) (w-byte w (if x 1 0)))

(defun w-string (w x)
  "Write a length-prefixed string.  X may be a byte vector or a Lisp string."
  (let ((b (to-u8v x)))
    (w-u32 w (length b))
    (w-raw w b)))

(defun w-name-list (w names)
  "Write a name-list from a list of strings."
  (w-string w (format nil "~{~a~^,~}" names)))

(defun integer->be (n)
  "Minimal big-endian byte vector of non-negative integer N (empty for 0)."
  (if (zerop n)
      (make-array 0 :element-type '(unsigned-byte 8))
      (let* ((nbytes (ceiling (integer-length n) 8))
             (out (make-array nbytes :element-type '(unsigned-byte 8))))
        (dotimes (i nbytes out)
          (setf (aref out (- nbytes 1 i)) (logand (ash n (* -8 i)) #xff))))))

(defun w-mpint (w n)
  "Write a multiple-precision integer (RFC 4251).  Handles non-negative N (the
   case SSH uses for DH/RSA); a leading zero byte is added when the high bit is
   set so the value reads as positive."
  (cond ((zerop n) (w-u32 w 0))
        ((minusp n) (error "conch: negative mpint not supported"))
        (t (let ((b (integer->be n)))
             (if (>= (aref b 0) #x80)
                 (progn (w-u32 w (1+ (length b))) (w-byte w 0) (w-raw w b))
                 (w-string w b))))))

;;; ---- reader ----------------------------------------------------------------
(defstruct (reader (:constructor make-reader (data &optional (pos 0))))
  (data nil :type u8v)
  (pos 0 :type fixnum))

(defun r-remaining (r) (- (length (reader-data r)) (reader-pos r)))

(defun r-byte (r)
  (prog1 (aref (reader-data r) (reader-pos r)) (incf (reader-pos r))))

(defun r-raw (r n)
  (let ((p (reader-pos r)))
    (incf (reader-pos r) n)
    (subseq (reader-data r) p (+ p n))))

(defun r-u32 (r)
  (let ((v 0)) (dotimes (i 4 v) (setf v (logior (ash v 8) (r-byte r))))))

(defun r-u64 (r)
  (let ((v 0)) (dotimes (i 8 v) (setf v (logior (ash v 8) (r-byte r))))))

(defun r-bool (r) (/= 0 (r-byte r)))

(defun r-string (r)
  "Read a length-prefixed string as a byte vector."
  (r-raw r (r-u32 r)))

(defun r-cstring (r) (utf8->string (r-string r)))

(defun r-name-list (r)
  (let ((s (utf8->string (r-string r))))
    (if (zerop (length s)) '()
        (loop for start = 0 then (1+ pos)
              for pos = (position #\, s :start start)
              collect (subseq s start pos)
              while pos))))

(defun u32-at (v i)
  "The big-endian u32 at V[I]."
  (logior (ash (aref v i) 24) (ash (aref v (+ i 1)) 16) (ash (aref v (+ i 2)) 8) (aref v (+ i 3))))

(defun be->integer (bytes)
  "Non-negative integer from big-endian BYTES."
  (let ((v 0)) (loop for b across bytes do (setf v (logior (ash v 8) b))) v))

(defun r-mpint (r) (be->integer (r-string r)))
