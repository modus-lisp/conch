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
(defconstant +fxp-extended+ 200) (defconstant +fxp-extended-reply+ 201)
(defconstant +fxp-attrs+ 105)
;; open flags
(defconstant +fxf-read+ 1)   (defconstant +fxf-write+ 2)  (defconstant +fxf-append+ 4)
(defconstant +fxf-creat+ 8)  (defconstant +fxf-trunc+ 16) (defconstant +fxf-excl+ 32)
;; status codes
(defconstant +fx-ok+ 0) (defconstant +fx-eof+ 1)
(defconstant +fx-no-such-file+ 2) (defconstant +fx-permission-denied+ 3)

;;; MULTIPLEXED.  A request is sent and returns its id (SFTP-REQUEST); its response is waited for by that id
;;; (SFTP-RESPONSE).  Any number may be in flight on the one channel: the server answers each in turn, and a
;;; response read while waiting for another is set aside under its own id until its owner asks.  So
;;;   - a transfer keeps *SFTP-WINDOW* reads (or writes) in flight, and a link's latency is paid once a
;;;     window, not once a chunk -- what makes SFTP fast over a long or slow connection;
;;;   - a set of folders is looked into at once (SFTP-PEEK-DIRS), a few round trips for all of them;
;;;   - an app's *WAIT-HOOK*, run while conch waits, may itself send requests and wait for them, at a SAFE
;;;     POINT (AT-SAFE-POINT-P): a tap is answered while a preload or a transfer is still in flight.

(defparameter *sftp-chunk* 32768 "Bytes a read or a write asks for.")
(defparameter *sftp-window* 128
  "Reads (or writes) a transfer keeps in flight: a transfer moves at most this many chunks a round trip, so 16
   (512 KB) held a 50 ms link to 9 MB/s and a 400 ms one to 1.2.  At 400 ms, 64 made it 3.2 both ways and 128
   made downloads 4.3; uploads stay at 3.2 past 64, where OpenSSH's own window (2 MB a channel) stops them --
   the writes past it wait in the channel, harmless.")

(defstruct sftp chan (idc 0) version
  (pending (make-hash-table))       ; responses read on another request's way: id -> (type . payload)
  (asked (make-hash-table)))        ; ids sent and not yet answered to their request

(defun sftp-next-id (s) (setf (sftp-idc s) (logand (1+ (sftp-idc s)) #xffffffff)))

;;; ---- framing ---------------------------------------------------------------
(defun sftp-send (s type payload)
  (let ((w (make-writer)))
    (w-u32 w (+ 1 (length payload)))
    (w-byte w type) (w-raw w payload)
    (let ((*mid-sftp* t))                          ; a message is written whole, or not at all
      (chan-write (sftp-chan s) (writer-bytes w)))))

(defun sftp-recv (s)
  "Read one SFTP packet; return (values TYPE reader-over-payload).  Until its first byte is in, a SAFE
   POINT; from then until its last, not -- its length can arrive split across channel packets too."
  (let ((c (sftp-chan s)))
    (loop while (< (chan-avail c) 4)
          do (when (or (chan-eof c) (chan-closed c))
               (ssh-error "channel: unexpected EOF (have ~d, need 4)" (chan-avail c)))
             (let ((*mid-sftp* (or *mid-sftp* (plusp (chan-avail c)))))
               (chan-await-data c)))
    (let* ((len (be->integer (chan-read-exact c 4)))
           (data (let ((*mid-sftp* t)) (chan-read-exact c len))))
      (values (aref data 0) (make-reader data 1)))))

(defun sftp-request (s type write-body)
  "Send a request of TYPE -- its id, then what WRITE-BODY (a function of a writer) writes -- and return
   its id, without waiting for the response."
  (let ((id (sftp-next-id s)) (w (make-writer)))
    (w-u32 w id)
    (when write-body (funcall write-body w))
    (sftp-send s type (writer-bytes w))
    (setf (gethash id (sftp-asked s)) t)
    id))

(defun sftp-response (s id)
  "The response to request ID: (values TYPE reader), the reader past the id.  Others read on the way are
   set aside for their own requests.  An ID already answered is an error, not a wait for ever: a clean-up
   cannot always know whether the response it drains was read before the error that brought it there."
  (let ((pending (sftp-pending s)))
    (unless (gethash id (sftp-asked s)) (ssh-error "sftp: request ~d is not waiting for a response" id))
    (loop
      (let ((ready (gethash id pending)))
        (when ready
          (remhash id pending)
          (remhash id (sftp-asked s))
          (return (values (car ready) (make-reader (cdr ready) 0)))))
      (let ((got (catch 'sftp-rescan
                   (let ((*rescan* (lambda () (nth-value 1 (gethash id pending)))))
                     (multiple-value-list (sftp-recv s))))))
        (when got                                  ; NIL: a hook's request read it meanwhile -- look again
          (destructuring-bind (type r) got
            (let ((rid (r-u32 r)))
              (if (= rid id)
                  (progn (remhash id (sftp-asked s)) (return (values type r)))
                  (setf (gethash rid pending) (cons type (subseq (reader-data r) (reader-pos r))))))))))))

(defun sftp-call (s type write-body)
  "One request and its response: (values TYPE reader)."
  (sftp-response s (sftp-request s type write-body)))

(defun skip-attrs (r)
  "Consume an ATTRS structure and discard it."
  (let ((flags (r-u32 r)))
    (when (logtest flags 1) (r-u64 r))            ; size
    (when (logtest flags 2) (r-u32 r) (r-u32 r))  ; uid gid
    (when (logtest flags 4) (r-u32 r))            ; permissions
    (when (logtest flags 8) (r-u32 r) (r-u32 r))  ; atime mtime
    (when (logtest flags #x80000000)
      (dotimes (i (r-u32 r)) (r-string r) (r-string r)))))

(defun read-attrs (r)
  "Read an ATTRS structure: a plist of what it carries -- :SIZE :UID :GID :PERMISSIONS :ATIME :MTIME
   (times in seconds since 1970)."
  (let ((flags (r-u32 r)) (a '()))
    (when (logtest flags 1) (setf (getf a :size) (r-u64 r)))
    (when (logtest flags 2) (setf (getf a :uid) (r-u32 r) (getf a :gid) (r-u32 r)))
    (when (logtest flags 4) (setf (getf a :permissions) (r-u32 r)))
    (when (logtest flags 8) (setf (getf a :atime) (r-u32 r) (getf a :mtime) (r-u32 r)))
    (when (logtest flags #x80000000)
      (dotimes (i (r-u32 r)) (r-string r) (r-string r)))
    a))

(defun attrs-kind (attrs)
  ":DIRECTORY :FILE :SYMLINK or :OTHER, from the permissions' file-type bits (NIL when not sent)."
  (let ((p (getf attrs :permissions)))
    (when p
      (case (logand p #o170000)
        (#o040000 :directory) (#o100000 :file) (#o120000 :symlink) (t :other)))))

(defstruct (sftp-entry (:constructor %make-sftp-entry (name attrs)))
  "One directory entry: its NAME and ATTRS (READ-ATTRS's plist)."
  name attrs)

(defun sftp-entry-size (e) (getf (sftp-entry-attrs e) :size))
(defun sftp-entry-mtime (e) (getf (sftp-entry-attrs e) :mtime))
(defun sftp-entry-kind (e) (attrs-kind (sftp-entry-attrs e)))

(defun sftp-fail (r what)
  "Signal the failure in the STATUS response R (past its id)."
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

;;; ---- responses -------------------------------------------------------------
(defun sftp-handle-of (s id what)
  (multiple-value-bind (type r) (sftp-response s id)
    (cond ((= type +fxp-handle+) (r-string r))
          ((= type +fxp-status+) (sftp-fail r what))
          (t (ssh-error "sftp: expected HANDLE, got ~d" type)))))

(defun sftp-ok-of (s id what)
  (multiple-value-bind (type r) (sftp-response s id)
    (unless (= type +fxp-status+) (ssh-error "sftp: expected STATUS, got ~d" type))
    (let ((code (r-u32 r)))
      (unless (= code +fx-ok+) (ssh-error "sftp ~a failed (code ~d): ~a" what code (r-cstring r)))
      t)))

(defun sftp-data-of (s id)
  "A READ's response: the bytes, or NIL at end of file."
  (multiple-value-bind (type r) (sftp-response s id)
    (cond ((= type +fxp-data+) (r-string r))
          ((= type +fxp-status+)
           (let ((code (r-u32 r)))
             (if (= code +fx-eof+) nil (ssh-error "sftp read failed (code ~d): ~a" code (r-cstring r)))))
          (t (ssh-error "sftp: expected DATA/STATUS, got ~d" type)))))

(defun sftp-names-of (s id &key attrs)
  "A READDIR's response: a batch of names -- with ATTRS, SFTP-ENTRY structs -- or NIL at its end."
  (multiple-value-bind (type r) (sftp-response s id)
    (cond ((= type +fxp-name+)
           (let ((count (r-u32 r)) (names '()))
             (dotimes (i count)
               (let ((name (r-cstring r)))
                 (r-cstring r)                         ; the longname, ls -l style: not used
                 (push (if attrs (%make-sftp-entry name (read-attrs r)) (progn (skip-attrs r) name))
                       names)))
             (nreverse names)))
          ((= type +fxp-status+)
           (let ((code (r-u32 r)))
             (if (= code +fx-eof+) nil (ssh-error "sftp readdir failed (code ~d)" code))))
          (t (ssh-error "sftp: expected NAME/STATUS, got ~d" type)))))

;;; ---- requests --------------------------------------------------------------
(defun %open-request (s path flags &optional mode)
  (sftp-request s +fxp-open+ (lambda (w)
                               (w-string w path) (w-u32 w flags)
                               (if mode (progn (w-u32 w 4) (w-u32 w mode)) (w-u32 w 0)))))  ; ATTRS
(defun %handle-request (s type handle)
  (sftp-request s type (lambda (w) (w-string w handle))))
(defun %path-request (s type path)
  (sftp-request s type (lambda (w) (w-string w path))))
(defun %read-request (s handle offset length)
  (sftp-request s +fxp-read+ (lambda (w) (w-string w handle) (w-u64 w offset) (w-u32 w length))))
(defun %write-request (s handle offset data)
  (sftp-request s +fxp-write+ (lambda (w) (w-string w handle) (w-u64 w offset) (w-string w data))))

(defun sftp-open-file (s path flags &optional mode)
  (sftp-handle-of s (%open-request s path flags mode) "open"))

(defun sftp-close (s handle)
  (sftp-ok-of s (%handle-request s +fxp-close+ handle) "close"))

(defun sftp-read-chunk (s handle offset length)
  "Return up to LENGTH bytes at OFFSET, or NIL at EOF."
  (sftp-data-of s (%read-request s handle offset length)))

(defun sftp-write-chunk (s handle offset data)
  (sftp-ok-of s (%write-request s handle offset data) "write"))

;;; ---- high-level operations -------------------------------------------------
(defun %progress (progress done total)
  "Call PROGRESS with DONE and TOTAL bytes; its :ABORT ends the transfer."
  (when (and progress (eq (funcall progress done total) :abort))
    (error 'ssh-error :message "transfer cancelled")))

(defun sftp-get (s remote-path local-path &key progress)
  "Download REMOTE-PATH to LOCAL-PATH, straight into the file, *SFTP-WINDOW* reads in flight.  PROGRESS,
   when given, is called with the bytes so far and the file's size (NIL if the server does not say) as
   they come; returning :ABORT cancels -- the partial file is deleted.  Returns bytes transferred."
  ;; the size and the open, asked together; both answered inside the protection below, so a cancel while
  ;; waiting for either still leaves nothing unread and no handle open
  (let* ((stat-id (%path-request s +fxp-stat+ remote-path))
         (open-id (%open-request s remote-path +fxf-read+))
         (total nil) (handle nil)
         (queue '())                ; requests in flight, oldest first: (offset length id)
         (next 0)                   ; the next offset to ask for
         (done 0) (eof nil) (ok nil))
    (labels ((ask (offset length)
               (list offset length (%read-request s handle offset length)))
             (fill-window ()
               ;; past a known size there is nothing to ask for; with no size, ask until a read says EOF
               (loop while (and (not eof) (< (length queue) *sftp-window*)
                                (or (null total) (< next total) (null queue)))
                     do (setf queue (nconc queue (list (ask next *sftp-chunk*))))
                        (incf next *sftp-chunk*))))
      (unwind-protect
           (progn
             (setf total (multiple-value-bind (type r) (multiple-value-prog1 (sftp-response s stat-id) (setf stat-id nil))
                           (and (= type +fxp-attrs+) (getf (read-attrs r) :size))))
             (setf handle (prog1 (sftp-handle-of s open-id "open") (setf open-id nil)))
             (with-open-file (out local-path :element-type '(unsigned-byte 8) :direction :output
                                             :if-exists :supersede :if-does-not-exist :create)
               (%progress progress 0 total)
               (fill-window)
               (loop while queue
                     do (destructuring-bind (offset length id) (first queue)
                          ;; off the queue only once answered: a cancel while waiting leaves it there, to drain
                          (let ((data (prog1 (sftp-data-of s id) (pop queue))))
                            (cond ((null data) (setf eof t))
                                  (t (write-sequence data out)     ; responses are taken in order
                                     (incf done (length data))
                                     (when (< (length data) length)
                                       ;; a short read: the rest of that chunk, asked for at once and
                                       ;; taken next, so the file is still written in order
                                       (push (ask (+ offset (length data)) (- length (length data))) queue))
                                     (%progress progress done total)))
                            (fill-window)))))
             (setf ok t))
        ;; whatever is still in flight (a cancel, an error) is read and dropped, so nothing is left behind --
        ;; without the hook, whose cancel would cut the clean-up short too
        (let ((*wait-hook* nil))
          (when stat-id (ignore-errors (sftp-response s stat-id)))
          (when open-id (setf handle (ignore-errors (sftp-handle-of s open-id "open"))))
          (dolist (q queue) (ignore-errors (sftp-response s (third q))))
          (when handle (ignore-errors (sftp-close s handle))))
        (unless ok (ignore-errors (delete-file local-path)))))
    done))

(defun sftp-read-range (s remote-path offset length)
  "LENGTH bytes of REMOTE-PATH from OFFSET (fewer at its end; none past it), as a byte vector: the file opened,
   every chunk of the range asked for at once, the file closed -- about two round trips, whatever the size of
   the file.  A look into a file too big (or too slow) to fetch."
  (let* ((open-id (%open-request s remote-path +fxf-read+))
         (handle nil) (queue '())
         (out (make-array length :element-type '(unsigned-byte 8)))
         (got 0))
    (unwind-protect
         (progn
           (setf handle (prog1 (sftp-handle-of s open-id "open") (setf open-id nil)))
           (loop for at from 0 below length by *sftp-chunk*
                 do (setf queue (nconc queue (list (list at (min *sftp-chunk* (- length at))
                                                         (%read-request s handle (+ offset at)
                                                                        (min *sftp-chunk* (- length at))))))))
           ;; responses in order; a short read leaves a gap, filled by asking again for the rest of it
           (loop while queue
                 do (destructuring-bind (at want id) (first queue)
                      (let ((data (prog1 (sftp-data-of s id) (pop queue))))
                        (cond ((null data))                                 ; past the end of the file
                              (t (replace out data :start1 at)
                                 (setf got (max got (+ at (length data))))
                                 (when (< (length data) want)
                                   (push (list (+ at (length data)) (- want (length data))
                                               (%read-request s handle (+ offset at (length data))
                                                              (- want (length data))))
                                         queue))))))))
      (let ((*wait-hook* nil))
        (when open-id (setf handle (ignore-errors (sftp-handle-of s open-id "open"))))
        (dolist (q queue) (ignore-errors (sftp-response s (third q))))
        (when handle (ignore-errors (sftp-close s handle)))))
    (if (= got length) out (subseq out 0 got))))

(defun sftp-write-range (s remote-path offset bytes)
  "Write the byte vector BYTES over REMOTE-PATH from OFFSET, in place: the file opened for writing but neither
   created nor truncated, so every other byte stays as it was (a write past the end grows it).  A peephole
   edit, however big the file -- about two round trips.  Returns the bytes written."
  (let* ((open-id (%open-request s remote-path +fxf-write+))
         (handle nil) (queue '()))
    (unwind-protect
         (progn
           (setf handle (prog1 (sftp-handle-of s open-id "open") (setf open-id nil)))
           (loop for at from 0 below (length bytes) by *sftp-chunk*
                 do (setf queue (nconc queue (list (%write-request s handle (+ offset at)
                                                                   (subseq bytes at (min (length bytes)
                                                                                         (+ at *sftp-chunk*))))))))
           (loop while queue do (progn (sftp-ok-of s (first queue) "write") (pop queue)))
           (let ((h handle)) (setf handle nil) (sftp-close s h)))     ; a write's close can fail: say so
      (let ((*wait-hook* nil))
        (when open-id (setf handle (ignore-errors (sftp-handle-of s open-id "open"))))
        (dolist (id queue) (ignore-errors (sftp-response s id)))
        (when handle (ignore-errors (sftp-close s handle)))))
    (length bytes)))

(defun sftp-put (s local-path remote-path &key progress)
  "Upload LOCAL-PATH to REMOTE-PATH, *SFTP-WINDOW* writes in flight.  PROGRESS as for SFTP-GET, called as
   writes are acknowledged (a cancelled upload leaves what was written).  Returns bytes transferred."
  (with-open-file (in local-path :element-type '(unsigned-byte 8))
    (let* ((len (file-length in))
           (open-id (%open-request s remote-path (logior +fxf-write+ +fxf-creat+ +fxf-trunc+) #o644))
           (handle nil)
           (queue '()) (off 0) (acked 0))
      (flet ((take ()
               (destructuring-bind (n id) (first queue)
                 (sftp-ok-of s id "write")
                 (pop queue)
                 (incf acked n)
                 (%progress progress acked len))))
        (unwind-protect
             (progn
               (setf handle (prog1 (sftp-handle-of s open-id "open") (setf open-id nil)))
               (%progress progress 0 len)
               (loop
                 (let* ((buf (make-array *sftp-chunk* :element-type '(unsigned-byte 8)))
                        (n (read-sequence buf in)))
                   (when (zerop n) (return))
                   (setf queue (nconc queue (list (list n (%write-request s handle off (if (= n (length buf))
                                                                                            buf
                                                                                            (subseq buf 0 n)))))))
                   (incf off n)
                   (when (>= (length queue) *sftp-window*) (take))))
               (loop while queue do (take)))
          (let ((*wait-hook* nil))
            (when open-id (setf handle (ignore-errors (sftp-handle-of s open-id "open"))))
            (dolist (q queue) (ignore-errors (sftp-response s (second q))))
            (when handle (ignore-errors (sftp-close s handle)))))
        acked))))

(defparameter *sftp-readdir-window* 3 "READDIRs a listing keeps in flight (each answers the next batch).")

(defun %dots-out (batch)
  (remove-if (lambda (e) (member (if (stringp e) e (sftp-entry-name e)) '("." "..") :test #'string=)) batch))

(defun sftp-map-entries (s path fn)
  "List directory PATH a batch at a time, as the server sends them: FN gets each batch, a list of
   SFTP-ENTRY structs (\".\" and \"..\" left out), in the server's order -- so a UI can show a big
   directory as it arrives.  *SFTP-READDIR-WINDOW* reads in flight.  Returns the number of entries."
  (let ((open-id (%path-request s +fxp-opendir+ path)) (handle nil) (n 0) (queue '()) (eof nil))
    (unwind-protect
         (progn
           (setf handle (prog1 (sftp-handle-of s open-id "opendir") (setf open-id nil)))
           (loop repeat *sftp-readdir-window* do (setf queue (nconc queue (list (%handle-request s +fxp-readdir+ handle)))))
           (loop while queue
                 do (let ((batch (prog1 (sftp-names-of s (first queue) :attrs t) (pop queue))))
                      (if (null batch)
                          (setf eof t)
                          (let ((batch (%dots-out batch)))
                            (when batch
                              (incf n (length batch))
                              (funcall fn batch))))
                      (unless eof (setf queue (nconc queue (list (%handle-request s +fxp-readdir+ handle))))))))
      (let ((*wait-hook* nil))
        (when open-id (setf handle (ignore-errors (sftp-handle-of s open-id "opendir"))))
        (dolist (id queue) (ignore-errors (sftp-response s id)))
        (when handle (ignore-errors (sftp-close s handle)))))
    n))

(defun sftp-entries (s path)
  "List directory PATH: SFTP-ENTRY structs (name and attributes), \".\" and \"..\" left out."
  (let ((entries '()))
    (sftp-map-entries s path (lambda (batch) (setf entries (nconc entries batch))))
    entries))

(defun sftp-peek-dirs (s paths &key (batches 2))
  "A look into each directory in PATHS at once: their first BATCHES batches of entries.  All the opens go
   out together, then all the reads, then all the closes -- three round trips for the lot, not three for
   each.  Returns, in the order of PATHS, (PATH ENTRIES COMPLETE-P) for each that opened (COMPLETE-P: that
   was all of it); one that cannot be opened is left out.  Interrupted (a cancel), it still reads what it
   had in flight and closes what it opened."
  (let ((opens (mapcar (lambda (p) (cons p (%path-request s +fxp-opendir+ p))) paths))
        (handles '()) (reads '()) (out '()))
    (unwind-protect
         (progn
           (loop for cell in opens
                 do (let ((h (handler-case (sftp-handle-of s (cdr cell) "opendir")
                               (ssh-error (e) (if (search "cancelled" (ssh-error-message e)) (error e) nil)))))
                      (setf (cdr cell) nil)                              ; answered: no longer in flight
                      (when h (push (cons (car cell) h) handles))))
           (setf handles (nreverse handles))
           (setf reads (loop for (p . h) in handles
                             collect (list p (loop repeat batches collect (%handle-request s +fxp-readdir+ h)))))
           (dolist (r reads)
             (destructuring-bind (p ids) r
               (let ((entries '()) (complete nil))
                 (loop while ids
                       do (let ((batch (handler-case (sftp-names-of s (first ids) :attrs t)
                                         (ssh-error (e) (if (search "cancelled" (ssh-error-message e)) (error e) nil)))))
                            (setf ids (rest ids) (second r) ids)          ; answered: no longer in flight
                            (if (and batch (not complete))
                                (setf entries (nconc entries (%dots-out batch)))
                                (setf complete t))))
                 (push (list p entries complete) out))))
           (nreverse out))
      ;; what is still in flight is read; what was opened is closed -- without the hook
      (let ((*wait-hook* nil))
        (loop for (p . id) in opens
              when id do (let ((h (ignore-errors (sftp-handle-of s id "opendir"))))
                           (when h (push (cons p h) handles))))
        (dolist (r reads) (dolist (id (second r)) (ignore-errors (sftp-response s id))))
        (let ((closes (loop for (p . h) in handles collect (%handle-request s +fxp-close+ h))))
          (dolist (id closes) (ignore-errors (sftp-response s id))))))))

(defun sftp-walk (s root fn &key (width 8) (reads 2))
  "Every folder under ROOT, and ROOT, listed -- WIDTH of them at once, READS readdirs in flight on each, depth
   first.  FN is called with (PATH ENTRIES) for each batch of a folder's entries as it comes (SFTP-ENTRY
   structs, \".\" and \"..\" left out), and returns the paths of the folders among them to go into (a symlink to
   a folder: the caller's choice); with (PATH :UNREADABLE) for a folder that cannot be opened or read; and
   with (PATH :DONE) once a folder is finished -- which may return folders to go into as well (a caller
   that must see all of a folder before it decides: its .gitignore, say, may come in its last batch).  For a disk-usage scan: a deep tree is listed with many round
   trips overlapping, not one folder after another.  Interrupted (a cancel), it reads what it had in flight and
   closes what it opened."
  (let ((pending (list root))
        (queue '())                          ; requests in flight, oldest first: (kind path id)
        (open 0)                             ; folders being listed
        (dirs (make-hash-table :test 'equal)))   ; path -> (handle reads-in-flight eof-p)
    (labels ((enqueue (op) (setf queue (nconc queue (list op))))
             (cancelled-p (e) (search "cancelled" (ssh-error-message e)))
             (open-next ()
               (loop while (and pending (< open width))
                     do (let ((p (pop pending)))
                          (incf open)
                          (enqueue (list :open p (%path-request s +fxp-opendir+ p))))))
             (ask (p st)
               (incf (second st))
               (enqueue (list :read p (%handle-request s +fxp-readdir+ (first st)))))
             (finish-if-done (p st)
               ;; at its end with nothing left in flight: closed, and done
               (when (and (third st) (zerop (second st)))
                 (enqueue (list :close p (%handle-request s +fxp-close+ (first st))))
                 (remhash p dirs)
                 (decf open)
                 (dolist (sub (funcall fn p :done)) (push sub pending)))))
      (unwind-protect
           (progn
             (open-next)
             (loop while queue
                   do (destructuring-bind (kind p id) (first queue)
                        (ecase kind
                          (:open
                           (let ((h (handler-case (sftp-handle-of s id "opendir")
                                      (ssh-error (e) (if (cancelled-p e) (error e) nil)))))
                             (pop queue)                              ; answered: no longer in flight
                             (if h
                                 (let ((st (list h 0 nil)))
                                   (setf (gethash p dirs) st)
                                   (dotimes (i reads) (ask p st)))
                                 (progn (decf open)
                                        (funcall fn p :unreadable)
                                        (dolist (sub (funcall fn p :done)) (push sub pending))))))
                          (:read
                           (let ((batch (handler-case (sftp-names-of s id :attrs t)
                                          (ssh-error (e) (if (cancelled-p e) (error e) :error))))
                                 (st (gethash p dirs)))
                             (pop queue)
                             (decf (second st))
                             (cond ((or (null batch) (eq batch :error))
                                    (when (and (eq batch :error) (not (third st))) (funcall fn p :unreadable))
                                    (setf (third st) t)
                                    (finish-if-done p st))
                                   (t
                                    (unless (third st) (ask p st))  ; the next batch asked for at once
                                    (let ((entries (%dots-out batch)))
                                      (when entries
                                        (dolist (sub (funcall fn p entries)) (push sub pending))))))))
                          (:close
                           (pop queue)
                           (ignore-errors (sftp-response s id)))))
                      (open-next)))
        ;; a cancel: what is in flight read and dropped, what is open closed -- without the hook
        (let ((*wait-hook* nil))
          (dolist (op queue) (ignore-errors (sftp-response s (third op))))
          (let ((closes (loop for st being the hash-values of dirs
                              collect (%handle-request s +fxp-close+ (first st)))))
            (dolist (id closes) (ignore-errors (sftp-response s id)))))))))

(defun %sftp-path-op (s type path what)
  (multiple-value-bind (rtype r) (sftp-response s (%path-request s type path))
    (cond ((= rtype +fxp-attrs+) (read-attrs r))
          ((= rtype +fxp-status+) (sftp-fail r what))
          (t (ssh-error "sftp: expected ATTRS, got ~d" rtype)))))

(defun sftp-stat (s path)
  "PATH's attributes (READ-ATTRS's plist), following a symlink."
  (%sftp-path-op s +fxp-stat+ path "stat"))

(defun sftp-lstat (s path)
  "PATH's attributes, of a symlink itself."
  (%sftp-path-op s +fxp-lstat+ path "lstat"))

(defun sftp-rename (s from to)
  "Rename (or move) FROM to TO on the server."
  (sftp-ok-of s (sftp-request s +fxp-rename+ (lambda (w) (w-string w from) (w-string w to))) "rename"))

(defun sftp-ls (s path)
  "List directory PATH; return a list of entry name strings."
  (let ((handle (sftp-opendir s path)) (names '()))
    (unwind-protect
         (loop for batch = (sftp-readdir s handle)
               while batch do (setf names (nconc names batch)))
      (sftp-close s handle))
    names))

(defun sftp-opendir (s path)
  (sftp-handle-of s (%path-request s +fxp-opendir+ path) "opendir"))

(defun sftp-readdir (s handle &key attrs)
  "Return a batch of filename strings -- or with ATTRS, SFTP-ENTRY structs -- or NIL at
   end-of-directory."
  (sftp-names-of s (%handle-request s +fxp-readdir+ handle) :attrs attrs))

(defun sftp-realpath (s path)
  "Canonicalize PATH on the server; return the absolute path string."
  (multiple-value-bind (type r) (sftp-response s (%path-request s +fxp-realpath+ path))
    (cond ((= type +fxp-name+) (r-u32 r) (r-cstring r))
          ((= type +fxp-status+) (sftp-fail r "realpath"))
          (t (ssh-error "sftp: expected NAME, got ~d" type)))))

(defun sftp-mkdir (s path)
  (sftp-ok-of s (sftp-request s +fxp-mkdir+ (lambda (w) (w-string w path) (w-u32 w 0))) "mkdir"))

(defun sftp-rmdir (s path)
  (sftp-ok-of s (%path-request s +fxp-rmdir+ path) "rmdir"))

(defun sftp-remove (s path)
  (sftp-ok-of s (%path-request s +fxp-remove+ path) "remove"))

;;; ---- a folder and everything in it ----

(defun sftp-tree-contents (s root &key progress sizes stamps)
  "Everything under ROOT, counted: (values FILES DIRS BYTES), FILES the paths of its files (symlinks among
   them: a link is removed, not followed), DIRS its folders with their depth below ROOT, (path . depth), ROOT
   itself (depth 0) first.  SIZES: each file as (path . size) instead; STAMPS: as (path size mtime), the mtime
   in seconds since 1970.  PROGRESS is called with (files dirs
   bytes) as it goes; returning :ABORT cancels."
  (let ((files '()) (dirs (list (cons root 0))) (bytes 0) (depth (make-hash-table :test 'equal)))
    (setf (gethash root depth) 0)
    (sftp-walk s root
               (lambda (p entries)
                 (if (keywordp entries)
                     (progn (when (eq entries :unreadable)
                              (ssh-error "~a cannot be read, so it cannot be deleted whole" p))
                            nil)
                     (prog1
                         (loop for e in entries
                               for path = (if (string= p "/") (concatenate 'string "/" (sftp-entry-name e))
                                              (concatenate 'string p "/" (sftp-entry-name e)))
                               if (eq (sftp-entry-kind e) :directory)
                                 do (let ((d (1+ (gethash p depth))))
                                      (setf (gethash path depth) d)
                                      (push (cons path d) dirs))
                                 and collect path
                               else do (push (cond
                                              (stamps (list path (if (eq (sftp-entry-kind e) :symlink) nil (or (sftp-entry-size e) 0))
                                                            (sftp-entry-mtime e)))
                                              (sizes
                                                 ;; a symlink's size is the link's own: none, so it is read to its end
                                                 (cons path (if (eq (sftp-entry-kind e) :symlink) nil (or (sftp-entry-size e) 0))))
                                              (t path))
                                             files)
                                       (incf bytes (or (sftp-entry-size e) 0)))
                       (%progress (and progress (lambda (a b) (declare (ignore b)) (funcall progress a (length dirs) bytes)))
                                  (length files) nil)))))
    (values (nreverse files) (nreverse dirs) bytes)))

(defun sftp-delete-paths (s files dirs &key progress)
  "Remove FILES (paths), then DIRS ((path . depth), from SFTP-TREE-CONTENTS) deepest first -- *SFTP-WINDOW*
   requests in flight, a depth at a time for the folders, so a folder is never asked to go before what was in
   it.  What the server refuses is skipped, not fatal.  PROGRESS is called with (done total) as removals are
   answered; returning :ABORT stops (what is in flight is still answered).  Returns the refusals, a list of
   (path . message)."
  (let* ((total (+ (length files) (length dirs))) (done 0) (failures '()) (queue '()))
    (labels ((take ()
               (destructuring-bind (path id what) (first queue)
                 (handler-case (sftp-ok-of s id what)
                   (ssh-error (e) (if (search "cancelled" (ssh-error-message e))
                                      (error e)
                                      (push (cons path (ssh-error-message e)) failures))))
                 (pop queue)
                 (incf done)
                 (%progress progress done total)))
             (run (paths type what)
               (dolist (p paths)
                 (setf queue (nconc queue (list (list p (%path-request s type p) what))))
                 (when (>= (length queue) *sftp-window*) (take)))
               (loop while queue do (take))))
      (unwind-protect
           (progn
             (%progress progress 0 total)
             (run files +fxp-remove+ "remove")
             (let ((by-depth (sort (copy-list dirs) #'> :key #'cdr)))
               (loop while by-depth
                     do (let ((d (cdr (first by-depth))))
                          (run (loop while (and by-depth (= (cdr (first by-depth)) d))
                                     collect (car (pop by-depth)))
                               +fxp-rmdir+ "rmdir")))))
        (let ((*wait-hook* nil))
          (dolist (q queue) (ignore-errors (sftp-response s (second q)))))))
    (nreverse failures)))

(defun sftp-lstat-many (s paths)
  "Each of PATHS lstat'ed -- all asked at once, one round trip for the lot -- in order: its attributes, or NIL
   for one that is not there (or cannot be looked at)."
  (let ((ids (mapcar (lambda (p) (%path-request s +fxp-lstat+ p)) paths)) (out '()))
    (unwind-protect
         (loop while ids
               do (multiple-value-bind (type r) (sftp-response s (first ids))
                    (pop ids)
                    (push (and (= type +fxp-attrs+) (read-attrs r)) out)))
      (let ((*wait-hook* nil)) (dolist (id ids) (ignore-errors (sftp-response s id)))))
    (nreverse out)))

(defun sftp-statvfs (s path)
  "The filesystem PATH is on, by OpenSSH's statvfs@openssh.com extension: a plist of :SIZE :FREE (for the
   user: what is available to them) :USED, in bytes, and :FILES :FILES-FREE -- or NIL where the server does
   not have the extension."
  (multiple-value-bind (type r)
      (sftp-response s (sftp-request s +fxp-extended+ (lambda (w) (w-string w "statvfs@openssh.com") (w-string w path))))
    (when (= type +fxp-extended-reply+)
      (let* ((bsize (r-u64 r)) (frsize (r-u64 r)) (blocks (r-u64 r)) (bfree (r-u64 r)) (bavail (r-u64 r))
             (files (r-u64 r)) (ffree (r-u64 r)))
        (declare (ignore bsize))
        (list :size (* frsize blocks) :free (* frsize bavail) :used (* frsize (- blocks bfree))
              :files files :files-free ffree)))))

(defparameter *sftp-small-file* (* 4 32768)
  "Files up to this size SFTP-GET-MANY fetches together, a batch at a time; larger ones one by one.")

(defun sftp-get-many (s jobs &key progress on-file (batch 16))
  "Download JOBS, each (remote local size): small files *SFTP-SMALL-FILE* or less BATCH at a time -- their opens
   sent together, then their reads, then their closes, about three round trips for the batch -- and the rest
   one by one with SFTP-GET's own window.  A file that cannot be read is skipped, not fatal.  PROGRESS is
   called with (files-done bytes-done) as they finish; returning :ABORT stops (what is in flight is drained, a
   file part way is deleted).  ON-FILE is called with each job as its file is in, whole.  Returns the failures, a
   list of (remote . message)."
  (let ((done 0) (bytes 0) (failures '()))
    (labels ((tell () (%progress (and progress (lambda (a b) (declare (ignore b)) (funcall progress a bytes)))
                                 done nil))
             (failed (remote e) (push (cons remote (if (typep e 'ssh-error) (ssh-error-message e) (princ-to-string e)))
                                      failures))
             (cancel-p (e) (and (typep e 'ssh-error) (search "cancelled" (ssh-error-message e))))
             (small-batch (jobs)
               (let ((opens (mapcar (lambda (j) (list j (%open-request s (first j) +fxf-read+))) jobs))
                     (open '()) (reads '()) (closes '()))
                 (unwind-protect
                      (progn
                        ;; handles
                        (loop while opens
                              do (destructuring-bind (j id) (first opens)
                                   (let ((h (handler-case (sftp-handle-of s id "open")
                                              (ssh-error (e) (if (cancel-p e) (error e) (progn (failed (first j) e) nil))))))
                                     (pop opens)
                                     (when h (push (list j h) open)))))
                        (setf open (nreverse open))
                        ;; every chunk of every file, asked at once
                        (setf reads (loop for (j h) in open
                                          collect (list j h (loop for at from 0 below (max 1 (third j)) by *sftp-chunk*
                                                                  collect (%read-request s h at *sftp-chunk*)))))
                        (loop while reads
                              do (destructuring-bind (j h ids) (first reads)
                                   (declare (ignore h))
                                   (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
                                         (ok t))
                                     (loop while ids
                                           do (let ((data (handler-case (sftp-data-of s (first ids))
                                                            (ssh-error (e) (if (cancel-p e) (error e)
                                                                               (progn (when ok (failed (first j) e)) (setf ok nil) nil))))))
                                                (pop ids) (setf (third (first reads)) ids)
                                                (when data (loop for b across data do (vector-push-extend b out)))))
                                     (pop reads)
                                     (when ok
                                       (with-open-file (f (second j) :direction :output :element-type '(unsigned-byte 8)
                                                                     :if-exists :supersede :if-does-not-exist :create)
                                         (write-sequence out f))
                                       (incf bytes (length out))
                                       (when on-file (funcall on-file j)))
                                     (incf done)
                                     (tell)))))
                   (let ((*wait-hook* nil))
                     (dolist (o opens) (ignore-errors (let ((h (sftp-handle-of s (second o) "open"))) (push (list (first o) h) open))))
                     (dolist (r reads) (dolist (id (third r)) (ignore-errors (sftp-response s id))))
                     (setf closes (mapcar (lambda (o) (%handle-request s +fxp-close+ (second o))) open))
                     (dolist (id closes) (ignore-errors (sftp-response s id))))))))
      (let* ((small-p (lambda (j) (and (third j) (<= (third j) *sftp-small-file*))))  ; no size: read whole
             (small (remove-if-not small-p jobs))
             (large (remove-if small-p jobs)))
        (loop while small
              do (small-batch (loop repeat batch while small collect (pop small))))
        (dolist (j large)
          (let ((before bytes))
            (handler-case
                (progn
                  (sftp-get s (first j) (second j)
                            :progress (lambda (got total)
                                        (declare (ignore total))
                                        (setf bytes (+ before got))
                                        (and progress (funcall progress done bytes))))
                  (when on-file (funcall on-file j)))
              (ssh-error (e) (if (cancel-p e) (error e) (failed (first j) e)))))
          (incf done)
          (tell))))
    (nreverse failures)))
