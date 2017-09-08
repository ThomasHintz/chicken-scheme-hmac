; author: Thomas Hintz
; email: t@thintz.com
; license: bsd

(use test)
(use sha1 string-utils hmac)

(test-group "RFC2202 test vectors"
  (define (testv key msg expected)
    (test "Vector" expected (string->hex ((hmac key (sha1-primitive)) msg))))

  (testv (make-string 20 (integer->char #x0b))
         "Hi There"
         "b617318655057264e28bc0b6fb378c8ef146be00")
  (testv "Jefe"
         "what do ya want for nothing?"
         "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
  (testv "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
         (make-string 50 (integer->char #xcd))
         "4c9007f4026250c6bc8414f9bf50c86c2d7235da")
  (testv (make-string 20 (integer->char #xaa))
         (make-string 50 (integer->char #xdd))
         "125d7342b9ac11cd91a39af48aa17b4f63f175d3")
  (testv (make-string 20 (integer->char #x0c))
         "Test With Truncation"
         "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04")
  (testv (make-string 80 (integer->char #xaa))
         "Test Using Larger Than Block-Size Key - Hash Key First"
         "aa4ae5e15272d00e95705637ce8a3b55ed402112")
  (testv (make-string 80 (integer->char #xaa))
         "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
         "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"))

(test-exit)
