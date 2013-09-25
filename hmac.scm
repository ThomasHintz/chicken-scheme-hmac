; author: Thomas Hintz
; email: t@thintz.com
; license: bsd

(module hmac
  (hmac)

(import scheme chicken srfi-4 srfi-13)
(use message-digest-port)

(define (hmac key digest-primitive #!optional (block-size 64))
  (let ((key_ key))
    (when (> (string-length key_) block-size)
          (set! key_ (call-with-output-digest digest-primitive (cut display key_ <>) 'string)))
    (set! key_ (string-pad-right key_ block-size (integer->char 0)))
    (let ((ipad (string-map (lambda (c) (integer->char (bitwise-xor (char->integer c) #x36))) key_))
          (opad (string-map (lambda (c) (integer->char (bitwise-xor (char->integer c) #x5c))) key_)))
      (lambda (message)
        (call-with-output-digest
         digest-primitive
         (cut display
              (string-append opad
                             (call-with-output-digest
                              digest-primitive
                              (cut display (string-append ipad message) <>)
                              'string))
              <>)
         'string)))))

)
