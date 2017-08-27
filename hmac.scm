; author: Thomas Hintz
; email: t@thintz.com
; license: bsd

(module hmac
  (hmac hmac-primitive)

(import scheme chicken lolevel srfi-13)
(use message-digest-basic message-digest-item message-digest-update-item)

(define (hmac-primitive key digest-primitive)
  (let ((block-size (message-digest-primitive-block-length digest-primitive))
        (key_ key))
    (when (> (string-length key_) block-size)
      (set! key_ (message-digest-string digest-primitive key_ 'string)))
    (set! key_ (string-pad-right key_ block-size (integer->char 0)))
    (let ((ipad (string-map (lambda (c) (integer->char (bitwise-xor (char->integer c) #x36))) key_))
          (opad (string-map (lambda (c) (integer->char (bitwise-xor (char->integer c) #x5c))) key_)))
      (make-message-digest-primitive
        (lambda ()
          (initialize-message-digest digest-primitive))
        (message-digest-primitive-digest-length digest-primitive)
        (lambda (inner)
          (message-digest-update-string inner ipad))
        (lambda (inner blob n)
          (message-digest-update-object inner blob))
        (lambda (inner x)
          (finalize-message-digest!
            (let ((outer (initialize-message-digest digest-primitive)))
              (message-digest-update-string outer opad)
              (message-digest-update-string outer (finalize-message-digest inner 'string))
              outer)
            x))))))

(define (hmac key digest-primitive #!optional (result-form 'string))
  (lambda (message)
    (message-digest-object (hmac-primitive key digest-primitive) message result-form)))
)
