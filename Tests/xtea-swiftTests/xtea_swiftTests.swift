import XCTest
@testable import XTEA

final class xteaTests: XCTestCase {
    
    //    {
    //        "key": "f5ff9b28dc32c866e65d0706f6a2189c",
    //        "plaintext": "646d1ff04ff2dd13",
    //        "ciphertext": "7d8800c594531b78"
    //    }
    
    func testEncryptionSampleCaseFromOurTestVectors() throws {
        let key = XTEA.Key(k0: 0xf5ff9b28, k1: 0xdc32c866, k2: 0xe65d0706, k3: 0xf6a2189c)
        let plainText = XTEA.Data(v0: 0x646d1ff0, v1: 0x4ff2dd13)
        
        let encrypted = XTEA.encipher(data: plainText, key: key)
        
        XCTAssertEqual(encrypted, XTEA.Data(v0: 0x7d8800c5, v1: 0x94531b78))

        let decrypted = XTEA.decipher(data: encrypted, key: key)
        
        XCTAssertEqual(decrypted, plainText)
    }
    
    struct XTEATestVector: Decodable {
        let key: String
        let plaintext: String
        let ciphertext: String
    }
    

    func testTestVectorCollection() throws {

        let url = try XCTUnwrap(Bundle.module.url(forResource: "xteaTestVectors", withExtension: "json"))
        let data = try Data(contentsOf: url)
        let testVectors = try JSONDecoder().decode([XTEATestVector].self, from: data)

        for vector in testVectors {
            let plainText = try XCTUnwrap(XTEA.Data(vector.plaintext))
            let key = try XCTUnwrap(XTEA.Key(vector.key))
            let ciphertext = try XCTUnwrap(XTEA.Data(vector.ciphertext))

            let encrypted = XTEA.encipher(data: plainText, key: key)
            XCTAssertEqual(encrypted, ciphertext)
            
            let decrypted = XTEA.decipher(data: ciphertext, key: key)
            XCTAssertEqual(decrypted, plainText)
        }
    }
}

extension String {
    subscript(safe bounds: CountableRange<Int>) -> String? {
        var start = index(startIndex, offsetBy: bounds.lowerBound, limitedBy: endIndex) ?? endIndex
        if bounds.lowerBound < 0 {
            start = startIndex
        }
        var end = index(startIndex, offsetBy: bounds.upperBound, limitedBy: endIndex) ?? endIndex
        if bounds.upperBound < 0 {
            end = startIndex
        }
        return String(self[start ..< end])
    }
}
extension XTEA.Data {
    init?(_ str: String) {
        guard let v0 = UInt32(str[safe: 0..<8]!, radix: 16),
              let v1 = UInt32(str[safe: 8..<16]!, radix: 16) else {
            return nil
        }
        
        self.init(v0: v0, v1: v1)
    }
}

extension XTEA.Key {
    init? (_ str: String) {
        guard let k0 = UInt32(str[safe:  0..<8]!, radix: 16),
              let k1 = UInt32(str[safe:  8..<16]!, radix: 16),
              let k2 = UInt32(str[safe: 16..<24]!, radix: 16),
              let k3 = UInt32(str[safe: 24..<32]!, radix: 16) else {
            return nil
        }
        
        self.init(k0: k0, k1: k1, k2: k2, k3: k3)
    }
}
