#!/usr/bin/env swift

import Foundation

// Test the specific challenge from your error
let challengeHex = "76cc5d3cfab9f2fd03e44bbcee41c3af6e9e4fba7902f26927b4b9a40a03e23f"

extension Data {
    init?(hexString: String) {
        let length = hexString.count / 2
        var data = Data(capacity: length)
        for i in 0 ..< length {
            let j = hexString.index(hexString.startIndex, offsetBy: i * 2)
            let k = hexString.index(j, offsetBy: 2)
            let bytes = hexString[j ..< k]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
        }
        self = data
    }
}

guard let challengeData = Data(hexString: challengeHex) else {
    print("Failed to convert hex to data")
    exit(1)
}

print("Challenge hex: \(challengeHex)")
print("Challenge data count: \(challengeData.count)")
print("Challenge bytes: \(challengeData.map { String(format: "%02hhx", $0) }.joined())")

// Check for Algorand tags
let prefixes = ["appID", "arc", "aB", "aD", "aO", "aP", "aS", "AS", "BH", "B256", "BR", "CR", "GE", "KP", "MA", "MB", "MX", "NIC", "NIR", "NIV", "NPR", "OT1", "OT2", "PF", "PL", "Program", "ProgData", "PS", "PK", "SD", "SpecialAddr", "STIB", "spc", "spm", "spp", "sps", "spv", "TE", "TG", "TL", "TX", "VO"]
let prefixBytes = prefixes.map { $0.data(using: .ascii)! }
let hasAlgorandTags = prefixBytes.contains { challengeData.starts(with: $0) }

print("Has Algorand tags: \(hasAlgorandTags)")

// Convert to byte object
var byteObject: [String: Any] = [:]
for (index, byte) in challengeData.enumerated() {
    byteObject[String(index)] = Int(byte)
}

print("Byte object: \(byteObject)")
print("All values in valid range (0-255): \(byteObject.values.allSatisfy { ($0 as? Int) ?? -1 >= 0 && ($0 as? Int) ?? -1 <= 255 })")

// Check if we have exactly 32 properties
print("Byte object has \(byteObject.keys.count) keys")
print("Expected keys 0-31 present: \((0...31).allSatisfy { byteObject.keys.contains(String($0)) })")
