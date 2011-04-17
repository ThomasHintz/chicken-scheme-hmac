; author: Thomas Hintz
; email: t@thintz.com
; license: bsd

(use test)
(use sha1 string-utils)

(test-group "HMAC"
            (test "Short Key and Message"
                  "64608bd9aa157cdfbca795bf9a727fc191a50b66"
                  (string->hex ((hmac "hi" (sha1-primitive) 64) "food is good")))

            (test "Long Key, Short Message"
                  "511387216297726a7947c6006f5be89711662b1f"
                  (string->hex ((hmac "hi my name is the big bad wolf" (sha1-primitive) 64) "hi")))

            (test "Short Key, Long Message (Longer than blocksize)"
                  "73dc948bab4e0c65b1e5d18ae3694a39a4788bee"
                  (string->hex ((hmac "key" (sha1-primitive) 64) "this is a really long message that is going to being run through this hmac test to make sure that it works correctly.")))

            (test "Larger Blocksize"
                  "3dbf833dc1e13c88f0366efaa2ec7d89399c5c1a"
                  (string->hex ((hmac "key key key" (sha1-primitive) 256) "hi what is your name?")))

            (test "Smaller Blocksize"
                  "dd9547893c27d1af459601bb571c6da8941ac00c"
                  (string->hex ((hmac "key key key" (sha1-primitive) 16) "hi what is your name?"))))

(test-exit)