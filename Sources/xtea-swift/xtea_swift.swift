import Foundation

/*
 
 Reference implementation from https://en.wikipedia.org/wiki/XTEA
 
 
 /* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */

 void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
     unsigned int i;
     uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
     for (i=0; i < num_rounds; i++) {
         v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
         sum += delta;
         v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
     }
     v[0]=v0; v[1]=v1;
 }
 */


/// Encrypt
///  @parameters:
///  - data: the data to encrypt, 64 bits.
///  - key: the key to use to encrypt `data`. 128 bits.
public func xteaEncrypt(data: XTEA.Data, key: XTEA.Key) -> XTEA.Data {
    return data
}

public enum XTEA {
    /// A 128 bit key, stored as 4 UInt32s
    public struct Key {
        let k0: UInt32
        let k1: UInt32
        let k2: UInt32
        let k3: UInt32
    }
    
    public struct Data: Equatable {
        let v0: UInt32
        let v1: UInt32
    }
}
