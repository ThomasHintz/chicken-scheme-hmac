; author: Thomas Hintz
; email: t@thintz.com
; license: bsd

(module hmac
  (hmac)

(import scheme chicken srfi-4 srfi-13)
(use message-digest-port)

(define (hmac key digest-primitive #!optional (block-size 64))
  (when (> (string-length key) block-size)
    (set! key (call-with-output-digest digest-primitive (cut display key <>) 'string)))
  (set! key (string-pad-right key block-size (integer->char 0)))
  (let ((ipad (string-map (lambda (c) (integer->char (bitwise-xor (char->integer c) #x36))) key))
	(opad (string-map (lambda (c) (integer->char (bitwise-xor (char->integer c) #x5c))) key)))
    (lambda (message)
      (call-with-output-digest
        digest-primitive
        (cut display
             (string-append opad
                            (call-with-output-digest
                              digest-primitive
                              (cut display (string-append ipad message) <>)
                              string))
             <>)
        'string))))

)
