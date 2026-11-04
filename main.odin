package main

import "core:fmt"
import "core:slice"
import "core:math/rand"

import "./rsa"
import "core:crypto/hash"
import "core:math/big"

main :: proc () {
    thing : [8]u8 = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }
    thing_hash := hash.hash_bytes(.SHA256, thing[:])

    key_prv, key_pub := rsa.keygen()
    fmt.println(key_prv)


    cipher := rsa.encrypt(&key_pub, thing[:])
    data := rsa.decrypt(&key_prv, cipher)

    fmt.println(cipher)
    fmt.println(data)




    // m : big.Int
    // big.int_from_bytes_little(&m, thing_hash[:])
    // r : big.Int
    // big.int_set_from_integer(&r, 15)
    // e : big.Int
    // big.int_set_from_integer(&e, rsa.public_key_e(&key_pub))

    // n_bytes_len := rsa.public_key_n(&key_pub, nil)
    // n_bytes := make([]u8, n_bytes_len)
    // _ = rsa.public_key_n(&key_pub, n_bytes)
    // n : big.Int
    // big.int_from_bytes_little(&n, n_bytes)
    //
    // re : big.Int
    // big.internal_powmod(&re, &r, &e, &n)
    // mp : big.Int
    // big.internal_mulmod(&mp, &m, &re, &n)

    // mpp := make([]u8, rsa.public_key_size(&key_pub))
    // big.int_to_bytes_little(&mp, mpp)

    // fmt.println(thing_hash)
    // fmt.println(mpp)







    fmt.println("Hello, World!")
}
