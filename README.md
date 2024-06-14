# XTEA Swift implementation
## Summary
This is a Swift implementation of the [Extended Tiny Encryption Algorithm (XTEA)](https://en.wikipedia.org/wiki/XTEA).


## Usage

``` swift
import XTEA
```

Use the `XTEA` functions to encipher/decipher data.

``` swift
    let key = XTEA.Key(k0: 0xf5ff9b28, k1: 0xdc32c866, k2: 0xe65d0706, k3: 0xf6a2189c)
    let plainText = XTEA.Data(v0: 0x646d1ff0, v1: 0x4ff2dd13)
    
    let encrypted = XTEA.encipher(data: plainText, key: key)
    
    ...
    
    val decrypted = XTEA.decipher(data: cipherText, key: key)
```
 
Optionally, you can specify the number of XTEA rounds to perform (default: 32, the recommended number) using the `rounds` parameter: 

``` swift
    let encrypted = XTEA.encipher(data: plainText, key: key, rounds: 36)
  
    val decrypted = XTEA.decipher(data: cipherText, key: key, rounds: 36)
```

