import XCTest
@testable import xtea

final class xteaTests: XCTestCase {
    
    //    {
    //        "key": "f5ff9b28dc32c866e65d0706f6a2189c",
    //        "plaintext": "646d1ff04ff2dd13",
    //        "ciphertext": "7d8800c594531b78"
    //    }
    
    func testEncryptionSampleCaseFromOurTestVectors() throws {
        let key = XTEA.Key(k0: 0xf5ff9b28, k1: 0xdc32c866, k2: 0xe65d0706, k3: 0xf6a2189c)
        let plainText = XTEA.Data(v0: 0x646d1ff0, v1: 0x4ff2dd13)
        
        let encrypted = xteaEncrypt(data: plainText, key: key)
        
        XCTAssertEqual(encrypted, XTEA.Data(v0: 0x7d8800c5, v1: 0x94531b78))

        let decrypted = xteaDecrypt(cipherText: encrypted, key: key)
        
        XCTAssertEqual(decrypted, plainText)
    }
}


