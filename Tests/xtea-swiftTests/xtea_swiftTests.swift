import XCTest
@testable import xtea

final class xteaTests: XCTestCase {
    func testEncryption() throws {
        let result = xteaEncrypt(data: XTEA.Data(v0: 1, v1: 2), key: XTEA.Key(k0: 1, k1: 2, k2: 3, k3: 4))
        
        XCTAssertEqual(result, XTEA.Data(v0: 1, v1: 2))
    }
}
