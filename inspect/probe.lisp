;;;; probe.lisp — foundation smoke test against a real OpenSSH server:
;;;; version exchange + parse the server's KEXINIT name-lists.
(require :asdf)
;; Sibling repos, found relative to this file so the workspace can live anywhere.
(asdf:initialize-source-registry
 (let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
   `(:source-registry (:tree ,(merge-pathnames "../../" here)) :inherit-configuration)))
(asdf:load-system :conch)
(in-package :conch)

(multiple-value-bind (sock stream) (tcp-connect "127.0.0.1" 2222)
  (let ((conn (make-ssh-conn :socket sock :stream stream)))
    (format t "~&client id: ~a~%" *client-id*)
    (format t "server id: ~a~%" (exchange-versions conn))
    (let* ((p (expect-msg conn +msg-kexinit+ "KEXINIT"))
           (r (make-reader p 1)))
      (r-raw r 16)                              ; cookie
      (format t "~%negotiated by the server (KEXINIT):~%")
      (format t "  kex        : ~{~a~^ ~}~%" (r-name-list r))
      (format t "  host-key   : ~{~a~^ ~}~%" (r-name-list r))
      (format t "  cipher c->s: ~{~a~^ ~}~%" (r-name-list r))
      (format t "  cipher s->c: ~{~a~^ ~}~%" (r-name-list r))
      (format t "  mac c->s   : ~{~a~^ ~}~%" (r-name-list r))
      (format t "  mac s->c   : ~{~a~^ ~}~%" (r-name-list r)))
    (ignore-errors (sb-bsd-sockets:socket-close sock))
    (format t "~%OK — codec + transport spoke to OpenSSH.~%")))
