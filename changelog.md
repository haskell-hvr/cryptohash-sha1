## 0.11.100.1

 - Use `__builtin_bswap{32,64}` only with GCC >= 4.3

## 0.11.100.0

 - new `hmac` and `hmaclazy` functions providing HMAC-SHA1
   computation conforming to RFC2104 and RFC2202

## 0.11.7.2

 - switch to 'safe' FFI for calls where overhead becomes negligible
 - removed inline assembly in favour of portable C constructs
 - fix 32bit length overflow bug in `hash` function
 - fix inaccurate context-size
 - add context-size verification to incremental API operations
 - fix unaligned memory-accesses

## 0.11.7.1

 - first version forked off `cryptohash-0.11.7` release
