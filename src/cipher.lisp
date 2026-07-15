;;;; cipher.lisp — chacha20-poly1305@openssh.com (and later aes-gcm/ctr).
;;;; Implemented in a subsequent step; stubs so the transport layer links.
(in-package #:conch)

(defun cipher-send-packet (conn payload)
  (declare (ignore conn payload))
  (error "conch: encrypted cipher not yet implemented"))

(defun cipher-recv-packet (conn)
  (declare (ignore conn))
  (error "conch: encrypted cipher not yet implemented"))
