(use sha1 srfi-4 srfi-4-utils)

; taken from example at http://wiki.call-cc.org/drupal-xml-rpc
(define (sha1-hmac key)
  (when (> (string-length key) 64) (set! key (sha1-binary-digest key)))
  (set! key (string-pad-right key 64 (integer->char 0)))
  (set! key (blob->u8vector (string->blob key)))
  (let ((ipad (blob->string (u8vector->blob (u8vector-map (lambda (v) (bitwise-xor v #x36)) key))))
        (opad (blob->string (u8vector->blob (u8vector-map (lambda (v) (bitwise-xor v #x5c)) key)))))
    (lambda (message)
      (sha1-binary-digest (string-append opad (sha1-binary-digest (string-append ipad message)))))))