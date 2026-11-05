package main

import "core:fmt"
import "core:slice"
import "core:math/rand"

import "./rsa"
import "core:crypto/hash"
import "core:math/big"

Test :: struct {
    a : u32,
    b : f32,
}

main :: proc () {
    key_prv, key_pub := rsa.keygen()
    key_prv1, key_pub1 := rsa.keygen()

    // thing : [8]u8 = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }
    thing := Test{ 69, 420.0 }

    cipher, result_en := rsa.encrypt_value(&key_pub1, thing)
    thingAnew, result_de := rsa.decrypt_value(&key_prv, cipher, Test)

    fmt.println(result_en, result_de, thing, thingAnew)





    // thing_hash := hash.hash_bytes(.SHA256, thing[:])
    //
    // r, r1 := rsa.blindGenerate(&key_pub)
    //
    // masked := rsa.blindMask(&key_pub, &r, thing_hash)
    // maskedSignature := rsa.sign_raw(&key_prv, masked)
    // signature := rsa.blindUnmask(&key_pub, &r1, maskedSignature)
    //
    // fmt.println(rsa.verify(&key_pub, thing[:], signature))






    fmt.println("Hello, World!")
}
