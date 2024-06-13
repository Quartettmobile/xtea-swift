import XCTest
@testable import xtea

final class xteaTests: XCTestCase {
    func testEncryption() throws {
        let result = xteaEncrypt(data: Data([1]), key: Data([1]))
        
        XCTAssertEqual(result, Data([1]))
    }
}
