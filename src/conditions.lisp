;;;; conditions.lisp — conch error hierarchy.

(in-package #:conch)

(define-condition ssh-error (error)
  ((message :initarg :message :initform nil :reader ssh-error-message))
  (:report (lambda (c s) (format s "SSH error: ~a" (ssh-error-message c)))))

(define-condition ssh-protocol-error (ssh-error) ()
  (:report (lambda (c s) (format s "SSH protocol error: ~a" (ssh-error-message c)))))

(define-condition ssh-host-key-error (ssh-error)
  ((fingerprint :initarg :fingerprint :initform nil :reader ssh-host-key-fingerprint))
  (:report (lambda (c s) (format s "SSH host-key error: ~a" (ssh-error-message c)))))

(define-condition ssh-auth-error (ssh-error) ()
  (:report (lambda (c s) (format s "SSH authentication error: ~a" (ssh-error-message c)))))

(defun ssh-error (fmt &rest args)
  (error 'ssh-error :message (apply #'format nil fmt args)))

(defun ssh-protocol-error (fmt &rest args)
  (error 'ssh-protocol-error :message (apply #'format nil fmt args)))
