; author: Thomas Hintz
; email: t@thintz.com
; license: bsd

(module hmac
  (hmac)

(import scheme chicken srfi-4 srfi-13)
(use srfi-4-utils message-digest-port)

; taken from example at http://wiki.call-cc.org/drupal-xml-rpc
(define (hmac key digest-primitive #!optional (block-size 64))
  (when (> (string-length key) block-size)
    (set! key (call-with-output-digest digest-primitive (cut display key <>) 'string)))
  (set! key (string-pad-right key block-size (integer->char 0)))
  (set! key (blob->u8vector (string->blob key)))
  (let ((ipad (blob->string (u8vector->blob (u8vector-map (lambda (v) (bitwise-xor v #x36)) key))))
        (opad (blob->string (u8vector->blob (u8vector-map (lambda (v) (bitwise-xor v #x5c)) key)))))
    (lambda (message)
      (call-with-output-digest digest-primitive (cut display (string-append opad (call-with-output-digest digest-primitive (cut display (string-append ipad message) <>) 'string)) <>) 'string))))

)