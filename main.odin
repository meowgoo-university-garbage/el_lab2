package main

import "core:fmt"
import "core:slice"
import "core:math/rand"

import "./rsa"
import "core:crypto/hash"
import "core:math/big"

main :: proc () {
    key_prv, key_pub := rsa.keygen()

    thing : [8]u8 = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }
    thing_hash := hash.hash_bytes(.SHA256, thing[:])

    r, r1 := rsa.blindGenerate(&key_pub)

    masked := rsa.blindMask(&key_pub, &r, thing_hash)
    maskedSignature := rsa.sign_raw(&key_prv, masked)
    signature := rsa.blindUnmask(&key_pub, &r1, maskedSignature)

    fmt.println(rsa.verify(&key_pub, thing[:], signature))






    fmt.println("Hello, World!")
}
