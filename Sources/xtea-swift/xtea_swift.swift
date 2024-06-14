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

// magic constant, see https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm for a tiny bit more info.
private let delta: UInt32 = 0x9E3779B9

/// Public enum used as a namespace for XTEA
public enum XTEA {
    
    /// A 128 bit key, stored as 4 UInt32s
    public struct Key {
        let k0: UInt32
        let k1: UInt32
        let k2: UInt32
        let k3: UInt32
        
        public init(k0: UInt32, k1: UInt32, k2: UInt32, k3: UInt32) {
            self.k0 = k0
            self.k1 = k1
            self.k2 = k2
            self.k3 = k3
        }
    }
    
    /// XTEA data, used both for plain text and encrypted data.
    public struct Data: Equatable {
        let v0: UInt32
        let v1: UInt32
        
        public init(v0: UInt32, v1: UInt32) {
            self.v0 = v0
            self.v1 = v1
        }
    }
    

    /// Encrypt.
    /// - Parameters:
    ///   - data: the data to encrypt. 64 bits.
    ///   - key: the key to use to encrypt `data`. 128 bits.
    ///   - rounds: The number of XTEA cycles to use when encrypting. One XTEA round is two Feistel cypher rounds.
    /// - Returns: The encrypted data
    /// - Note: This function is intentionally named `encipher` to follow the Wikipedia naming.
    public static func encipher(data: XTEA.Data, key: XTEA.Key, rounds: Int = 32) -> XTEA.Data {

        // magic constant, see https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm for a tiny bit more info.
        let delta: UInt32 = 0x9E3779B9
        var sum: UInt32 = 0
        
        // input data
        var v0: UInt32 = data.v0
        var v1: UInt32 = data.v1

        let key = [key.k0, key.k1, key.k2, key.k3]

        // this is where the magic happens.
        // See https://www.cix.co.uk/~klockstone/xtea.pdf for a description of XTEA, and
        // https://link.springer.com/chapter/10.1007/3-540-60590-8_29 for the original
        // TEA algorithm
        for _ in 1...rounds {
            v0 &+= (((v1 << 4) ^ (v1 >> 5)) &+ v1) ^ (sum &+ key[Int(sum & 3)])
            sum &+= delta
            v1 &+= (((v0 << 4) ^ (v0 >> 5)) &+ v0) ^ (sum &+ key[Int((sum >> 11) & 3)])
        }

        return XTEA.Data(v0: v0, v1: v1)
    }

    /// Decrypt
    /// - Parameters:
    ///   - cipherText: the encrypted data to decrypt. 64 bits.
    ///   - key: the key to use to decrypt `cipherText`. 128 bits.
    ///   - rounds: The number of XTEA cycles to use when decrypting. One XTEA round is two Feistel cypher rounds.
    /// - Returns: The decrypted plain text
    /// - Note: This function is intentionally named `encipher` to follow the Wikipedia naming.
    public static func decipher(cipherText: XTEA.Data, key: XTEA.Key, rounds: Int = 32) -> XTEA.Data {
        
        var sum: UInt32 = delta &* UInt32(rounds)

        // input data
        var v0: UInt32 = cipherText.v0
        var v1: UInt32 = cipherText.v1

        let key = [key.k0, key.k1, key.k2, key.k3]

        for _ in 1...rounds {
            v1 &-= (((v0 << 4) ^ (v0 >> 5)) &+ v0) ^ (sum &+ key[Int((sum >> 11) & 3)])
            sum &-= delta
            v0 &-= (((v1 << 4) ^ (v1 >> 5)) &+ v1) ^ (sum &+ key[Int(sum & 3)])
        }
        
        return XTEA.Data(v0: v0, v1: v1)
    }
    
}
