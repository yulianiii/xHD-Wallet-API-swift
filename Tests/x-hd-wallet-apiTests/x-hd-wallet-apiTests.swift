/*
 * Copyright (c) Algorand Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import BigInt
import MessagePack
import MnemonicSwift
@testable import x_hd_wallet_api
import XCTest

enum MyError: Error {
    case expectedError
}

// Helper function to create a Schema from JSON object
func createMockSchema(jsonSchema: [String: Any]) throws -> Schema {
    // Create a temporary file with the JSON schema
    let tempDir = FileManager.default.temporaryDirectory
    let tempFile = tempDir.appendingPathComponent(UUID().uuidString + ".json")

    let jsonData = try JSONSerialization.data(withJSONObject: jsonSchema, options: [])
    try jsonData.write(to: tempFile)

    let schema = try Schema(filePath: tempFile.path)

    // Clean up
    try? FileManager.default.removeItem(at: tempFile)

    return schema
}

final class XHDWalletAPITests: XCTestCase {
    func testSignWithValidateData_NoEncoding() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!
        let challenge = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })
        let authSchema = try Schema(filePath: "Tests/x-hd-wallet-apiTests/schemas/auth.request.json")
        let metadata = SignMetadata(encoding: .none, schema: authSchema)
        let valid = try wallet.validateData(data: challenge, metadata: metadata)
        XCTAssertTrue(valid)
        let bip44Path = wallet.getBIP44PathFromContext(context: .Address, account: 0, change: 0, keyIndex: 0)
        let signature = try wallet.sign(bip44Path: bip44Path, message: challenge, derivationType: .Peikert)
        XCTAssertEqual(signature.count, 64)
        let publicKey = try wallet.keyGen(context: .Address, account: 0, change: 0, keyIndex: 0)
        let isValid = wallet.verifyWithPublicKey(signature: signature, message: challenge, publicKey: publicKey)
        XCTAssertTrue(isValid)
    }

    func testSignWithValidateData_Base64() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!
        let challenge = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })
        let authSchema = try Schema(filePath: "Tests/x-hd-wallet-apiTests/schemas/auth.request.json")
        let metadata = SignMetadata(encoding: .base64, schema: authSchema)
        let base64Challenge = challenge.base64EncodedString()
        let encoded = base64Challenge.data(using: .utf8)!
        let valid = try wallet.validateData(data: encoded, metadata: metadata)
        XCTAssertTrue(valid)
        let bip44Path = wallet.getBIP44PathFromContext(context: .Address, account: 0, change: 0, keyIndex: 0)
        let signature = try wallet.sign(bip44Path: bip44Path, message: encoded, derivationType: .Peikert)
        XCTAssertEqual(signature.count, 64)
        let publicKey = try wallet.keyGen(context: .Address, account: 0, change: 0, keyIndex: 0)
        let isValid = wallet.verifyWithPublicKey(signature: signature, message: encoded, publicKey: publicKey)
        XCTAssertTrue(isValid)
    }

    func testSignWithValidateData_Msgpack() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!
        let challenge = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })
        let authSchema = try Schema(filePath: "Tests/x-hd-wallet-apiTests/schemas/auth.request.json")
        let metadata = SignMetadata(encoding: .msgpack, schema: authSchema)
        let encoded = MessagePack.pack(MessagePackValue.binary(challenge))
        let valid = try wallet.validateData(data: encoded, metadata: metadata)
        XCTAssertTrue(valid)
        let bip44Path = wallet.getBIP44PathFromContext(context: .Address, account: 0, change: 0, keyIndex: 0)
        let signature = try wallet.sign(bip44Path: bip44Path, message: encoded, derivationType: .Peikert)
        XCTAssertEqual(signature.count, 64)
        let publicKey = try wallet.keyGen(context: .Address, account: 0, change: 0, keyIndex: 0)
        let isValid = wallet.verifyWithPublicKey(signature: signature, message: encoded, publicKey: publicKey)
        XCTAssertTrue(isValid)
    }

    var c: XHDWalletAPI?

    override func setUpWithError() throws {
        let seed = try Mnemonic.deterministicSeedString(from: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice")
        c = XHDWalletAPI(seed: seed)
        guard c != nil else {
            throw NSError(domain: "XHDWalletAPITests", code: 1, userInfo: [NSLocalizedDescriptionKey: "XHDWalletAPI not initialized"])
        }
    }

    func testInitializationWithSeeds() throws {
        // Warning: never use these phrases!
        let seeds = [
            "bullet safe club entry raise radio boil tool among column boring giant rack panel minor gown pair hard pulse nice shy attract torch fun",
            "rapid guide picture cereal satoshi napkin affair task search enjoy kangaroo tube bridge learn churn tongue misery hotel race mandate verify multiply tower other",
            "thing brand only clap title duty vacuum picnic first basket brand tail tape give alarm brick inhale beauty banner text wasp judge wait borrow",
            "suffer rhythm sure sugar slice dynamic service trim bulb fence tube make smile table rally noodle crop subway industry club rely section idle frame",
            "valley fee chase mirror celery mom carpet fuel clown crisp interest town mosquito lamp please black giggle beach always fruit win tribe often bright",
            "fish increase monitor cruise deer start angle custom hand dwarf erode expose ancient fix surprise garment ecology bone soccer meadow build eye jelly legend",
            "ill catch planet summer blue clump stem rail express giraffe focus squirrel season behind field gentle online daughter select man parent castle awesome orchard",
            "gorilla piano secret fashion birth despair dumb gloom paddle tissue start demand primary robust enemy upset give neutral snap extend stereo task shoot load",
            "there reflect turkey language tragic hint destroy salt stamp party weasel pudding tent couch purse grace modify mansion among spell lamp beef trip uncover",
            "truth stand beyond payment october fury frame common advice bamboo casino panda nation valve siren kind inherit patch pair measure wage beauty forward rare",
            "suffer office prosper base subway arena avoid hamster betray animal angry method scare polar hunt lumber economy barely ticket coast ladder wheel acid trouble",
            "allow coast mandate galaxy setup fire beach pulse learn garbage good intact citizen mixture whip shrug shy rescue gown few hold today system galaxy",
            "law favorite talent thunder enroll muffin access else chef wedding wait rice squirrel logic surge rice social dove syrup jacket fitness embark able believe",
            "label enough energy reject weather post supply frown pattern super wrist sentence simple fetch capable burger lift pumpkin zone quit design anger supreme unveil",
            "offer program own fog cream echo scene marine enforce jacket supreme digital bread crowd captain poverty clerk because piano fortune shaft way library spawn",
            "crash subway naive party tower worth unique about soap conduct zone soon absurd notice air ride sail hurt regret embark father lock license gym",
            "brand mechanic access negative recall keen pepper popular century ten vessel tide napkin anchor option unit culture poet force theory tunnel boil foster solve",
            "hotel park shrug economy group holiday merit thank plunge protect lemon test kit report pig roof gasp weekend parade labor candy praise lawsuit human",
            "embrace acoustic define work teach bitter kiss mouse lamp melody mobile gasp sleep jazz kite next parrot trigger limb eye push oppose shiver certain",
            "duty rice trust section few more seven course sister curve destroy common list dad whip enhance empty asthma icon grace logic remove cherry black",
            "deny aunt maple dream humor lucky cluster beauty world fat age shock note list because decorate frown saddle buddy village heavy air win liquid"
        ]

        for seed in seeds {
            let seed = try Mnemonic.deterministicSeedString(from: seed)
            XCTAssertNotNil(XHDWalletAPI(seed: seed))
        }

        XCTAssertNil(XHDWalletAPI(seed: "invalid hex seed"))
    }

    func testHarden() throws {
        XCTAssertEqual(c!.harden(0), 2_147_483_648)
        XCTAssertEqual(c!.harden(1), 2_147_483_649)
        XCTAssertEqual(c!.harden(44), 2_147_483_692)
        XCTAssertEqual(c!.harden(283), 2_147_483_931)
    }

    func testGetBIP44PathFromContext() throws {
        let addressPath = c!.getBIP44PathFromContext(context: KeyContext.Address, account: 0, change: 0, keyIndex: 0)
        let identityPath = c!.getBIP44PathFromContext(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0)
        XCTAssertEqual(addressPath, [UInt32](arrayLiteral: 2_147_483_692, 2_147_483_931, 2_147_483_648, 0, 0))
        XCTAssertEqual(identityPath, [UInt32](arrayLiteral: 2_147_483_692, 2_147_483_648, 2_147_483_648, 0, 0))
    }

    func testDeriveNonHardened() throws {
        let kl = Data([168, 186, 128, 2, 137, 34, 217, 252, 250, 5, 92, 120, 174, 222, 85, 181, 197, 117, 188, 216, 213, 165, 49, 104, 237, 244, 95, 54, 217, 236, 143, 70])
        let cc = Data([121, 107, 146, 6, 236, 48, 225, 66, 233, 75, 121, 10, 152, 128, 91, 249, 153, 4, 43, 85, 4, 105, 99, 23, 78, 230, 206, 226, 208, 55, 89, 70])

        let expectedZZ = Data([79, 57, 235, 234, 215, 9, 72, 57, 157, 32, 34, 226, 81, 95, 29, 115, 250, 66, 232, 187, 16, 193, 209, 254, 140, 127, 122, 242, 224, 69, 122, 166, 31, 223, 82, 170, 49, 164, 3, 115, 96, 128, 159, 63, 116, 37, 118, 15, 167, 94, 148, 38, 50, 10, 126, 70, 3, 86, 36, 78, 199, 91, 146, 54])
        let expectedCCC = Data([98, 42, 235, 140, 228, 232, 27, 136, 136, 143, 220, 220, 32, 187, 77, 47, 254, 209, 231, 13, 224, 226, 108, 113, 167, 234, 93, 101, 160, 32, 37, 152, 216, 141, 148, 178, 77, 222, 78, 201, 150, 148, 186, 65, 223, 76, 237, 113, 104, 229, 170, 167, 224, 222, 193, 99, 251, 94, 222, 14, 82, 185, 232, 206])

        let (z, childChainCode) = c!.deriveNonHardened(kl: kl, cc: cc, index: 0)

        XCTAssertEqual(z, expectedZZ)
        XCTAssertEqual(childChainCode, expectedCCC)
    }

    func testDeriveHardened() throws {
        let kl = Data([168, 186, 128, 2, 137, 34, 217, 252, 250, 5, 92, 120, 174, 222, 85, 181, 197, 117, 188, 216, 213, 165, 49, 104, 237, 244, 95, 54, 217, 236, 143, 70])
        let kr = Data([148, 89, 43, 75, 200, 146, 144, 117, 131, 226, 38, 105, 236, 223, 27, 4, 9, 169, 243, 189, 85, 73, 242, 221, 117, 27, 81, 54, 9, 9, 205, 5])
        let cc = Data([121, 107, 146, 6, 236, 48, 225, 66, 233, 75, 121, 10, 152, 128, 91, 249, 153, 4, 43, 85, 4, 105, 99, 23, 78, 230, 206, 226, 208, 55, 89, 70])

        let expectedZZ = Data([241, 155, 222, 63, 177, 102, 52, 174, 88, 241, 56, 59, 144, 16, 74, 143, 9, 66, 66, 43, 208, 144, 253, 154, 211, 54, 107, 135, 59, 57, 54, 101, 184, 111, 121, 207, 178, 74, 118, 177, 0, 10, 69, 137, 96, 97, 246, 116, 206, 37, 118, 201, 90, 48, 254, 232, 249, 234, 191, 143, 116, 13, 40, 109])
        let expectedCCC = Data([113, 159, 183, 57, 127, 174, 86, 11, 68, 82, 114, 215, 136, 191, 242, 88, 45, 11, 66, 160, 140, 77, 60, 25, 130, 238, 210, 239, 247, 55, 117, 240, 141, 123, 149, 66, 11, 250, 54, 180, 175, 41, 166, 195, 76, 15, 154, 235, 246, 49, 203, 70, 79, 22, 94, 165, 138, 89, 21, 152, 23, 108, 180, 148])

        let (z, childChainCode) = c!.deriveHardened(kl: kl, kr: kr, cc: cc, index: c!.harden(44))
        XCTAssertEqual(z, expectedZZ)
        XCTAssertEqual(childChainCode, expectedCCC)
    }

    func testFromSeed() throws {
        let seed = Data([58, 255, 45, 180, 22, 184, 149, 236, 60, 249, 164, 248, 209, 233, 112, 188, 152, 25, 146, 14, 123, 244, 74, 94, 53, 4, 119, 175, 14, 245, 87, 177, 81, 27, 9, 134, 222, 191, 120, 221, 56, 199, 197, 32, 205, 68, 255, 124, 114, 49, 97, 143, 149, 142, 33, 239, 2, 80, 115, 58, 140, 25, 21, 234])
        let expectedKL = Data([168, 186, 128, 2, 137, 34, 217, 252, 250, 5, 92, 120, 174, 222, 85, 181, 197, 117, 188, 216, 213, 165, 49, 104, 237, 244, 95, 54, 217, 236, 143, 70])
        let expectedKR = Data([148, 89, 43, 75, 200, 146, 144, 117, 131, 226, 38, 105, 236, 223, 27, 4, 9, 169, 243, 189, 85, 73, 242, 221, 117, 27, 81, 54, 9, 9, 205, 5])
        let expectedC = Data([121, 107, 146, 6, 236, 48, 225, 66, 233, 75, 121, 10, 152, 128, 91, 249, 153, 4, 43, 85, 4, 105, 99, 23, 78, 230, 206, 226, 208, 55, 89, 70])
        let expectedOutput = expectedKL + expectedKR + expectedC
        let output = c!.fromSeed(seed)
        XCTAssertEqual(output, expectedOutput)
    }

    func testDeriveChildNodePrivate() throws {
        let indices = [c!.harden(UInt32(283)), UInt32(2_147_483_648)]
        let extendedKeys = [Data([48, 154, 117, 1, 19, 88, 124, 110, 192, 144, 35, 82, 48, 99, 166, 47, 18, 134, 206, 50, 87, 44, 30, 64, 138, 171, 185, 113, 221, 236, 143, 70, 76, 201, 164, 26, 123, 221, 6, 39, 132, 236, 107, 242, 76, 65, 18, 121, 215, 206, 105, 135, 176, 121, 240, 198, 111, 6, 17, 198, 125, 22, 245, 114, 141, 123, 149, 66, 11, 250, 54, 180, 175, 41, 166, 195, 76, 15, 154, 235, 246, 49, 203, 70, 79, 22, 94, 165, 138, 89, 21, 152, 23, 108, 180, 148]), Data([152, 225, 53, 235, 111, 189, 16, 80, 5, 187, 222, 103, 51, 25, 9, 175, 172, 210, 205, 151, 195, 80, 249, 179, 162, 157, 197, 181, 222, 236, 143, 70, 235, 179, 35, 29, 125, 172, 171, 5, 131, 195, 126, 183, 57, 159, 45, 69, 232, 136, 154, 57, 174, 63, 130, 164, 117, 24, 105, 139, 121, 92, 17, 211, 107, 102, 4, 2, 204, 196, 48, 71, 244, 82, 253, 123, 214, 63, 171, 147, 161, 188, 133, 206, 203, 205, 213, 26, 83, 29, 133, 228, 82, 216, 30, 127])]
        let expectedOutputs = [Data([152, 225, 53, 235, 111, 189, 16, 80, 5, 187, 222, 103, 51, 25, 9, 175, 172, 210, 205, 151, 195, 80, 249, 179, 162, 157, 197, 181, 222, 236, 143, 70, 235, 179, 35, 29, 125, 172, 171, 5, 131, 195, 126, 183, 57, 159, 45, 69, 232, 136, 154, 57, 174, 63, 130, 164, 117, 24, 105, 139, 121, 92, 17, 211, 107, 102, 4, 2, 204, 196, 48, 71, 244, 82, 253, 123, 214, 63, 171, 147, 161, 188, 133, 206, 203, 205, 213, 26, 83, 29, 133, 228, 82, 216, 30, 127]), Data([248, 91, 210, 62, 156, 144, 108, 177, 63, 167, 126, 1, 132, 58, 45, 178, 246, 252, 188, 221, 105, 104, 97, 54, 232, 92, 190, 228, 226, 236, 143, 70, 187, 122, 35, 69, 101, 182, 49, 122, 216, 252, 71, 107, 197, 176, 56, 18, 136, 95, 146, 175, 1, 151, 252, 83, 155, 22, 27, 106, 47, 67, 37, 75, 213, 25, 13, 246, 205, 204, 73, 226, 124, 111, 209, 124, 76, 32, 166, 121, 128, 234, 224, 65, 27, 230, 42, 228, 35, 106, 79, 138, 154, 149, 109, 227])]

        for i in 0 ..< indices.count {
            let output = try c!.deriveChildNodePrivate(extendedKey: extendedKeys[i], index: indices[i], g: BIP32DerivationType.Khovratovich)
            XCTAssertEqual(output, expectedOutputs[i])
            XCTAssertEqual(output.count, 96)
        }
    }

    func testTrunc256MinusGBits() throws {
        let testCases: [(zl: Data, g: BIP32DerivationType, expected: Data)] = [
            (
                Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                BIP32DerivationType.Peikert,
                Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00])
            ),
            (
                Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                BIP32DerivationType.Khovratovich,
                Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00])
            )
        ]

        for (zl, g, expected) in testCases {
            let result = c!.trunc256MinusGBits(zl: zl, g: g)
            XCTAssertEqual(result, expected, "Failed for g=\(g)")
        }
    }

    func testDeriveKey() throws {
        let rootkey = Data([168, 186, 128, 2, 137, 34, 217, 252, 250, 5, 92, 120, 174, 222, 85, 181, 197, 117, 188, 216, 213, 165, 49, 104, 237, 244, 95, 54, 217, 236, 143, 70, 148, 89, 43, 75, 200, 146, 144, 117, 131, 226, 38, 105, 236, 223, 27, 4, 9, 169, 243, 189, 85, 73, 242, 221, 117, 27, 81, 54, 9, 9, 205, 5, 121, 107, 146, 6, 236, 48, 225, 66, 233, 75, 121, 10, 152, 128, 91, 249, 153, 4, 43, 85, 4, 105, 99, 23, 78, 230, 206, 226, 208, 55, 89, 70])
        let bip44Path = [UInt32]([2_147_483_692, 2_147_483_931, 2_147_483_648, 0, 0])
        let expectedResultPublic = Data([98, 254, 131, 43, 122, 209, 5, 68, 190, 131, 55, 166, 112, 67, 94, 80, 100, 174, 74, 102, 231, 123, 215, 137, 9, 118, 91, 70, 181, 118, 166, 243])

        let outputPublic = try c!.deriveKey(rootKey: rootkey, bip44Path: bip44Path, isPrivate: false, derivationType: BIP32DerivationType.Khovratovich)
        XCTAssertEqual(outputPublic.prefix(32), expectedResultPublic)

        let expectedResultPrivate = Data([128, 16, 43, 185, 143, 170, 195, 253, 23, 137, 194, 198, 197, 89, 211, 113, 92, 217, 202, 194, 40, 214, 212, 176, 247, 106, 35, 70, 234, 236, 143, 70, 1, 174, 20, 40, 64, 137, 36, 62, 147, 107, 233, 27, 40, 35, 204, 20, 47, 117, 49, 53, 234, 255, 27, 174, 32, 211, 238, 199, 120, 112, 197, 68, 159, 146, 199, 144, 215, 171, 174, 224, 224, 10, 78, 193, 251, 120, 161, 212, 56, 232, 204, 247, 194, 186, 217, 160, 24, 165, 191, 154, 93, 81, 0, 117])
        let outputPrivate = try c!.deriveKey(rootKey: rootkey, bip44Path: bip44Path, isPrivate: true, derivationType: BIP32DerivationType.Khovratovich)
        XCTAssertEqual(outputPrivate, expectedResultPrivate)
    }

    func testDeriveChildNodePublic() throws {
        let seed = try Mnemonic.deterministicSeedString(from: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice")
        guard let data = Data(hexString: seed) else {
            return
        }

        let context = KeyContext.Address
        let account: UInt32 = 0
        let change: UInt32 = 0

        let bip44Path: [UInt32] = [c!.harden(44), c!.harden(283), c!.harden(0), 0]

        let derivationTypes: [BIP32DerivationType] = [.Khovratovich, .Peikert]

        for derivationType in derivationTypes {
            let walletRoot = try c!.deriveKey(
                rootKey: c!.fromSeed(data),
                bip44Path: bip44Path,
                isPrivate: false,
                derivationType: derivationType
            )

            let numPublicKeysToDerive = 10
            for i in 0 ..< numPublicKeysToDerive {
                let derivedKey = try c!.deriveChildNodePublic(extendedKey: walletRoot, index: UInt32(i), g: derivationType)
                let myKey = try c!.keyGen(context: context, account: account, change: change, keyIndex: UInt32(i), derivationType: derivationType)

                XCTAssertEqual(derivedKey.prefix(32), myKey, "The derived key does not match the expected key for derivation type \(derivationType)")
            }
        }
    }

    func testDeriveChildNodePublicHardenedChange() throws {
        let seed = try Mnemonic.deterministicSeedString(from: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice")
        guard let data = Data(hexString: seed) else {
            return
        }

        let context = KeyContext.Address
        let account: UInt32 = 0
        let change: UInt32 = 0

        // hardened change level
        let bip44Path: [UInt32] = [c!.harden(44), c!.harden(283), c!.harden(0), c!.harden(0)]

        let walletRoot = try c!.deriveKey(
            rootKey: c!.fromSeed(data),
            bip44Path: bip44Path,
            isPrivate: false,
            derivationType: BIP32DerivationType.Peikert
        )

        let numPublicKeysToDerive = 10
        for i in 0 ..< numPublicKeysToDerive {
            let derivedKey = try c!.deriveChildNodePublic(
                extendedKey: walletRoot,
                index: UInt32(i),
                g: BIP32DerivationType.Peikert
            )
            // Deriving from my own wallet where i DO have private information
            let myKey = try c!.keyGen(
                context: context,
                account: account,
                change: change,
                keyIndex: UInt32(i),
                derivationType: BIP32DerivationType.Peikert
            )

            // they should NOT match  since the `change` level (as part of BIP44) was hardened
            // derivedKey.prefix(32) ==  public key (excluding chaincode)
            XCTAssertNotEqual(derivedKey.prefix(32), myKey)
        }
    }

    func testDeriveChildNodePublicHardenedIndex() throws {
        let seed = try Mnemonic.deterministicSeedString(
            from: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice")
        guard let data = Data(hexString: seed) else {
            return
        }

        let bip44Path: [UInt32] = [c!.harden(44), c!.harden(283), c!.harden(0), 0]

        let walletRoot = try c!.deriveKey(
            rootKey: c!.fromSeed(data),
            bip44Path: bip44Path,
            isPrivate: false,
            derivationType: BIP32DerivationType.Peikert
        )

        // should fail to derive public keys with a hardened index
        XCTAssertThrowsError(
            try c!.deriveChildNodePublic(extendedKey: walletRoot, index: c!.harden(UInt32(0)), g: BIP32DerivationType.Peikert))
    }

    func testSafeLevelsOfDerivation() throws {
        // Test to see when, with a broken HMAC and a bad root key, the derivation fails.
        // Specifically, the derivedNonHardened is replaced and all 0xFF are returned.

        // To test Khovratovich case, replace the derivation type and the max safe levels with the commented values.
        let derivationType = BIP32DerivationType.Peikert // BIP32DerivationType.Khovratovich
        let maxSafeLevels = 8 // 67_108_864 // 2^26

        class BrokenXHDWalletAPI: XHDWalletAPI {
            // Override the deriveNonHardened method to return a fixed value
            // Specifically, all 1s (0xFF octets)
            override func deriveNonHardened(kl _: Data, cc _: Data, index _: UInt32) -> (z: Data, childChainCode: Data) {
                (Data(repeating: 0xFF, count: ED25519_SCALAR_SIZE * 2), Data((0 ..< CHAIN_CODE_SIZE * 2).map { _ in UInt8.random(in: 0 ... 255) }))
            }
        }

        let seedString = try Mnemonic.deterministicSeedString(from: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice")
        let mockClassInstance = BrokenXHDWalletAPI(seed: seedString)

        // prepare the root key to be as extremely unfavorable as possible
        var extendedKey = Data(repeating: 0xFF, count: ED25519_SCALAR_SIZE * 3)
        var bytes = [UInt8](extendedKey)

        // Clear bits 0, 1, 2, 253, 255
        bytes[0] &= ~(1 << 0) // Clear bit 0
        bytes[0] &= ~(1 << 1) // Clear bit 1
        bytes[0] &= ~(1 << 2) // Clear bit 2
        bytes[31] &= ~(1 << 5) // Clear bit 253 (bit 5 of the last byte)
        bytes[31] &= ~(1 << 7) // Clear bit 255 (bit 7 of the last byte)

        // Convert back to Data
        extendedKey = Data(bytes)

        var levels = 0
        var derived = extendedKey

        while true {
            do {
                derived = try mockClassInstance!.deriveChildNodePrivate(extendedKey: derived, index: 0, g: derivationType)
                levels += 1
                if levels > maxSafeLevels {
                    XCTFail("Derivation should have failed at level \(maxSafeLevels), but levels reached \(levels)")
                    break
                }
            } catch {
                XCTAssert(levels == maxSafeLevels, "Derivation failed at level \(levels) instead of \(maxSafeLevels)")
                break
            }
        }
    }

    func testDeriveMaxLevelsForKnownSeed() throws {
        let seed = try Mnemonic.deterministicSeedString(
            from: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice")
        guard let data = Data(hexString: seed) else {
            return
        }

        var derivationPath: [UInt32] = [
            c!.harden(44), c!.harden(283), c!.harden(0), 0, 0
        ] + Array(repeating: 0, count: 19)
        let derivationType = BIP32DerivationType.Peikert

        _ = try c!.deriveKey(
            rootKey: c!.fromSeed(data),
            bip44Path: derivationPath,
            isPrivate: true,
            derivationType: derivationType
        )

        derivationPath += [0]

        XCTAssert(derivationPath.count == 25)

        XCTAssertThrowsError(
            try c!.deriveKey(
                rootKey: c!.fromSeed(data),
                bip44Path: derivationPath,
                isPrivate: true,
                derivationType: derivationType
            ),
            "Expected deriveKey to throw an error"
        )
    }

    func testKeyGeneration() throws {
        let testVectors: [((KeyContext, UInt32, UInt32, UInt32), Data)] = [
            // derive key m'/44'/283'/0'/0/0
            ((KeyContext.Address, 0, 0, 0), Data([98, 254, 131, 43, 122, 209, 5, 68, 190, 131, 55, 166, 112, 67, 94, 80, 100, 174, 74, 102, 231, 123, 215, 137, 9, 118, 91, 70, 181, 118, 166, 243])),
            // derive key m'/44'/283'/0'/0/1
            ((KeyContext.Address, 0, 0, 1), Data([83, 4, 97, 0, 46, 172, 206, 192, 199, 181, 121, 89, 37, 170, 16, 74, 127, 180, 95, 133, 239, 10, 169, 91, 187, 91, 233, 59, 111, 133, 55, 173])),
            // derive key m'/44'/283'/0'/0/2
            ((KeyContext.Address, 0, 0, 2), Data([34, 129, 200, 27, 238, 4, 238, 3, 159, 164, 130, 194, 131, 84, 28, 106, 176, 108, 131, 36, 219, 111, 28, 197, 156, 104, 37, 46, 29, 88, 188, 179])),
            // derive key m'/44'/283'/1'/0/0
            ((KeyContext.Address, 1, 0, 0), Data([158, 18, 100, 63, 108, 0, 104, 220, 245, 59, 4, 218, 206, 214, 248, 193, 169, 10, 210, 28, 149, 74, 102, 223, 65, 64, 215, 147, 3, 22, 106, 103])),
            // derive key m'/44'/283'/1'/0/1
            ((KeyContext.Address, 1, 0, 1), Data([25, 254, 250, 164, 39, 200, 166, 251, 76, 248, 11, 184, 72, 233, 192, 195, 122, 162, 191, 76, 177, 156, 245, 172, 149, 21, 186, 30, 109, 152, 140, 186])),
            // derive key m'/44'/283'/2'/0/1
            ((KeyContext.Address, 2, 0, 1), Data([138, 93, 223, 98, 213, 26, 44, 80, 229, 29, 186, 212, 99, 67, 86, 204, 114, 49, 74, 129, 237, 217, 23, 172, 145, 218, 150, 71, 122, 159, 181, 176])),
            // derive key m'/44'/283'/3'/0/0
            ((KeyContext.Address, 3, 0, 0), Data([35, 88, 224, 242, 180, 101, 171, 62, 143, 85, 19, 157, 131, 22, 101, 77, 75, 227, 158, 187, 34, 54, 125, 54, 64, 159, 208, 42, 32, 176, 224, 23])),
            // derive key m'/44'/0'/0'/0/0
            ((KeyContext.Identity, 0, 0, 0), Data([182, 215, 238, 165, 175, 10, 216, 62, 223, 67, 64, 101, 158, 114, 240, 234, 43, 69, 102, 222, 31, 195, 182, 58, 64, 164, 37, 170, 190, 190, 94, 73])),
            // derive key m'/44'/0'/0'/0/1
            ((KeyContext.Identity, 0, 0, 1), Data([181, 206, 198, 118, 197, 162, 18, 158, 209, 190, 66, 35, 162, 112, 36, 57, 187, 178, 70, 47, 215, 123, 67, 242, 126, 47, 121, 253, 25, 74, 48, 162])),
            // derive key m'/44'/0'/0'/0/2
            ((KeyContext.Identity, 0, 0, 2), Data([67, 94, 94, 52, 70, 67, 29, 70, 37, 114, 171, 238, 27, 139, 173, 184, 134, 8, 144, 106, 106, 242, 123, 132, 151, 188, 207, 213, 3, 237, 182, 254])),
            // derive key m'/44'/0'/1'/0/0
            ((KeyContext.Identity, 1, 0, 0), Data([191, 99, 190, 131, 255, 249, 188, 157, 10, 235, 194, 49, 213, 3, 66, 17, 14, 82, 32, 36, 126, 80, 222, 55, 107, 71, 225, 84, 181, 211, 42, 62])),
            // derive key m'/44'/0'/1'/0/2
            ((KeyContext.Identity, 1, 0, 2), Data([70, 149, 142, 118, 219, 21, 21, 127, 64, 18, 39, 248, 172, 189, 183, 9, 36, 93, 202, 5, 85, 200, 232, 95, 86, 176, 210, 5, 46, 131, 77, 6])),
            // derive key m'/44'/0'/2'/0/1
            ((KeyContext.Identity, 2, 0, 1), Data([237, 177, 15, 255, 36, 164, 116, 93, 245, 47, 26, 10, 177, 174, 113, 179, 117, 45, 1, 156, 140, 36, 55, 212, 106, 184, 200, 230, 52, 167, 76, 212]))
        ]

        for (input, expected) in testVectors {
            let pk = try (c?.keyGen(context: input.0, account: input.1, change: input.2, keyIndex: input.3, derivationType: BIP32DerivationType.Khovratovich))!
            XCTAssertEqual(pk, expected)
        }
    }

    func testVerifyAlgoTxOld() throws {
        // this transaction wes successfully submitted to the network
        // https://testnet.explorer.perawallet.app/tx/UJG3NVCSCW5A63KPV35BPAABLXMXTTEM2CVUKNS4EML3H3EYGMCQ/
        let prefixEncodedTx = Data(base64Encoded: "VFiJo2FtdM0D6KNmZWXNA+iiZnbOAkeSd6NnZW6sdGVzdG5ldC12MS4womdoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk6IqJsds4CR5Zfo3JjdsQgYv6DK3rRBUS+gzemcENeUGSuSmbne9eJCXZbRrV2pvOjc25kxCBi/oMretEFRL6DN6ZwQ15QZK5KZud714kJdltGtXam86R0eXBlo3BheQ==")

        let bip44Path = (KeyContext.Address, UInt32(0), UInt32(0), UInt32(0))
        guard let pk = try c?.keyGen(context: bip44Path.0, account: bip44Path.1, change: bip44Path.2, keyIndex: bip44Path.3, derivationType: BIP32DerivationType.Khovratovich) else { return }
        guard let sig = try c?.signAlgoTransaction(context: bip44Path.0, account: bip44Path.1, change: bip44Path.2, keyIndex: bip44Path.3, prefixEncodedTx: prefixEncodedTx!, derivationType: BIP32DerivationType.Khovratovich) else { return }

        XCTAssertEqual(c?.verifyWithPublicKey(signature: sig, message: prefixEncodedTx!, publicKey: pk), true)
        XCTAssertEqual(try TestUtils.encodeAddress(bytes: pk), "ML7IGK322ECUJPUDG6THAQ26KBSK4STG4555PCIJOZNUNNLWU3Z3ZFXITA")
    }

    func testVerifyAlgoTx() throws {
        // this transaction wes successfully submitted to the network
        // https://testnet.explorer.perawallet.app/tx/UJG3NVCSCW5A63KPV35BPAABLXMXTTEM2CVUKNS4EML3H3EYGMCQ/
        let prefixEncodedTx = Data(base64Encoded: "VFiJo2FtdM0D6KNmZWXNA+iiZnbOAkeSd6NnZW6sdGVzdG5ldC12MS4womdoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk6IqJsds4CR5Zfo3JjdsQgYv6DK3rRBUS+gzemcENeUGSuSmbne9eJCXZbRrV2pvOjc25kxCBi/oMretEFRL6DN6ZwQ15QZK5KZud714kJdltGtXam86R0eXBlo3BheQ==")

        let bip44Path = (KeyContext.Address, UInt32(0), UInt32(0), UInt32(0))
        guard let pk = try c?.keyGen(context: bip44Path.0, account: bip44Path.1, change: bip44Path.2, keyIndex: bip44Path.3, derivationType: BIP32DerivationType.Khovratovich) else { return }
        guard let sig = try c?.sign(context: bip44Path.0, account: bip44Path.1, change: bip44Path.2, keyIndex: bip44Path.3, message: prefixEncodedTx!, derivationType: BIP32DerivationType.Khovratovich) else { return }

        XCTAssertEqual(c?.verifyWithPublicKey(signature: sig, message: prefixEncodedTx!, publicKey: pk), true)
        XCTAssertEqual(try TestUtils.encodeAddress(bytes: pk), "ML7IGK322ECUJPUDG6THAQ26KBSK4STG4555PCIJOZNUNNLWU3Z3ZFXITA")
    }

    func testMsgPackToSwift() throws {
        let nilValue: MessagePackValue = .nil
        XCTAssertTrue(c?.messagePackValueToSwift(nilValue) is NSNull)

        let boolValue: MessagePackValue = .bool(true)
        XCTAssertEqual(c?.messagePackValueToSwift(boolValue) as? Bool, true)

        let intValue: MessagePackValue = .int(-42)
        XCTAssertEqual(c?.messagePackValueToSwift(intValue) as? Int64, -42)

        let uintValue: MessagePackValue = .uint(42)
        XCTAssertEqual(c?.messagePackValueToSwift(uintValue) as? UInt64, 42)

        let floatValue: MessagePackValue = .float(42.0)
        XCTAssertEqual(c?.messagePackValueToSwift(floatValue) as? Float, 42.0)

        let doubleValue: MessagePackValue = .double(42.0)
        XCTAssertEqual(c?.messagePackValueToSwift(doubleValue) as? Double, 42.0)

        let strValue: MessagePackValue = .string("Hello")
        XCTAssertEqual(c?.messagePackValueToSwift(strValue) as? String, "Hello")

        let binaryValue: MessagePackValue = .binary(Data([1, 2, 3]))
        XCTAssertEqual(c?.messagePackValueToSwift(binaryValue) as? Data, Data([1, 2, 3]))

        let arrayValue: MessagePackValue = .array([.int(1), .int(2), .int(3)])
        XCTAssertEqual(c?.messagePackValueToSwift(arrayValue) as? [Int64], [1, 2, 3])

        let mapValue: MessagePackValue = .map(["key": .string("value")])
        XCTAssertEqual(c?.messagePackValueToSwift(mapValue) as? [String: String], ["key": "value"])

        let extendedValue: MessagePackValue = .extended(42, Data([1, 2, 3]))
        let expected: [String: Any] = ["type": 42, "data": Data([1, 2, 3])]
        let produced = c?.messagePackValueToSwift(extendedValue) as? [String: Any]
        XCTAssertEqual(produced?["type"] as? Int64, expected["type"] as? Int64)
        XCTAssertEqual(produced?["data"] as? Data, expected["data"] as? Data)
    }

    func testPrefixError() throws {
        // Algorand transaction bytes
        let txBytes = Data([84, 88, 138, 163, 97, 109, 116, 206, 0, 152, 150, 128, 163, 102, 101, 101, 205, 3, 232, 162, 102, 118, 1, 163, 103, 101, 110, 172, 100, 111, 99, 107, 101, 114, 110, 101, 116, 45, 118, 49, 162, 103, 104, 196, 32, 241, 58, 20, 104, 56, 57, 150, 147, 27, 180, 33, 136, 150, 19, 75, 8, 122, 48, 230, 57, 166, 3, 22, 66, 230, 213, 105, 153, 155, 59, 116, 186, 162, 108, 118, 205, 3, 233, 164, 110, 111, 116, 101, 196, 17, 116, 101, 115, 116, 32, 116, 114, 97, 110, 115, 97, 99, 116, 105, 111, 110, 33, 163, 114, 99, 118, 196, 32, 5, 203, 108, 214, 116, 145, 109, 203, 70, 233, 152, 142, 138, 129, 38, 88, 243, 206, 29, 133, 166, 17, 142, 91, 181, 120, 56, 133, 132, 103, 116, 129, 163, 115, 110, 100, 196, 32, 71, 235, 237, 176, 141, 136, 126, 190, 43, 187, 124, 13, 136, 150, 5, 71, 243, 107, 143, 109, 238, 238, 131, 63, 179, 59, 91, 63, 6, 64, 197, 130, 164, 116, 121, 112, 101, 163, 112, 97, 121])
        XCTAssert(c?.hasAlgorandTags(data: txBytes) == true)

        let hasPrefixedResult = try c?.validateData(data: txBytes, metadata: SignMetadata(encoding: Encoding.base64, schema: Schema(filePath: "Tests/x-hd-wallet-apiTests/schemas/auth.request.json")))
        XCTAssert(hasPrefixedResult == false)

        // Contain illegal prefix
        let msgsDoesHave =
            ["""
            TX
            {"text":"Hello, World!"}
            """,
            "VFiJo2FtdM0D6KNmZWXNA+iiZnbOAkeSd6NnZW6sdGVzdG5ldC12MS4womdoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk6IqJsds4CR5Zfo3JjdsQgYv6DK3rRBUS+gzemcENeUGSuSmbne9eJCXZbRrV2pvOjc25kxCBi/oMretEFRL6DN6ZwQ15QZK5KZud714kJdltGtXam86R0eXBlo3BheQ==" // base64
            ]

        let resultMX = c?.hasAlgorandTags(data: Data(msgsDoesHave[0].utf8))
        XCTAssert(resultMX!)

        let resultMXB64 = c?.hasAlgorandTags(data: Data(base64Encoded: msgsDoesHave[1])!)
        XCTAssert(resultMXB64!)

        let resultMXMsgP = c?.hasAlgorandTags(data: Data("TX".utf8) + Data(hexString: String("81a474657874ad48656c6c6f2c20576f726c6421".utf8))!)
        XCTAssert(resultMXMsgP!)

        // prepend "appID" in hexadecimal
        let resultMXMsgP2 = c?.hasAlgorandTags(data: Data(hexString: String("6170704944".utf8) + String("81a474657874ad48656c6c6f2c20576f726c6421".utf8))!)
        XCTAssert(resultMXMsgP2!)

        // Does not contain illegal prefix
        let msgsDoesNotHave =
            ["""
            {"text":"Hello, World!"}
            """,
            "eyJ0ZXh0IjoiSGVsbG8sIFdvcmxkISJ9" // base64
            ]

        let resultMXf = c?.hasAlgorandTags(data: Data(msgsDoesNotHave[0].utf8))
        XCTAssertFalse(resultMXf!)

        let resultMXB64f = c?.hasAlgorandTags(data: Data(base64Encoded: msgsDoesNotHave[1])!)
        XCTAssertFalse(resultMXB64f!)

        let resultMXMsgPf = c?.hasAlgorandTags(data: Data(hexString: String("81a474657874ad48656c6c6f2c20576f726c6421".utf8))!)
        XCTAssertFalse(resultMXMsgPf!)
    }

    func testSignAuthenticationChallenge32BytesBase64Old() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        // Generate 32 random bytes for authentication challenge
        let challenge = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })

        // Read auth schema file for authentication. 32 bytes challenge to sign
        let authSchema = try Schema(filePath: "Tests/x-hd-wallet-apiTests/schemas/auth.request.json")
        let metadata = SignMetadata(encoding: .base64, schema: authSchema)

        // Encode challenge as base64
        let base64Challenge = challenge.base64EncodedString()
        let encoded = base64Challenge.data(using: .utf8)!

        let signature = try wallet.signData(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0,
            data: encoded,
            metadata: metadata
        )

        XCTAssertEqual(signature.count, 64)

        let publicKey = try wallet.keyGen(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0
        )

        let isValid = wallet.verifyWithPublicKey(
            signature: signature,
            message: encoded,
            publicKey: publicKey
        )

        XCTAssertTrue(isValid)
    }

    func testSignAuthenticationChallenge32BytesMsgpackOld() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        // Generate 32 random bytes for authentication challenge
        let challenge = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })

        // Read auth schema file for authentication. 32 bytes challenge to sign
        let authSchema = try Schema(filePath: "Tests/x-hd-wallet-apiTests/schemas/auth.request.json")
        let metadata = SignMetadata(encoding: .msgpack, schema: authSchema)

        // Encode challenge as msgpack
        let encoded = MessagePack.pack(MessagePackValue.binary(challenge))

        let signature = try wallet.signData(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0,
            data: encoded,
            metadata: metadata
        )

        XCTAssertEqual(signature.count, 64)

        let publicKey = try wallet.keyGen(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0
        )

        let isValid = wallet.verifyWithPublicKey(
            signature: signature,
            message: encoded,
            publicKey: publicKey
        )

        XCTAssertTrue(isValid)
    }

    func testSignAuthenticationChallenge32BytesNoEncodingOld() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        // Generate 32 random bytes for authentication challenge
        let challenge = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })

        // Read auth schema file for authentication. 32 bytes challenge to sign
        let authSchema = try Schema(filePath: "Tests/x-hd-wallet-apiTests/schemas/auth.request.json")
        let metadata = SignMetadata(encoding: .none, schema: authSchema)

        let signature = try wallet.signData(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0,
            data: challenge,
            metadata: metadata
        )

        XCTAssertEqual(signature.count, 64)

        let publicKey = try wallet.keyGen(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0
        )

        let isValid = wallet.verifyWithPublicKey(
            signature: signature,
            message: challenge,
            publicKey: publicKey
        )

        XCTAssertTrue(isValid)
    }

    func testSignAuthenticationChallenge32BytesBase64() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        // Generate 32 random bytes for authentication challenge
        let challenge = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })

        // Read auth schema file for authentication. 32 bytes challenge to sign
        let authSchema = try Schema(filePath: "Tests/x-hd-wallet-apiTests/schemas/auth.request.json")
        let metadata = SignMetadata(encoding: .base64, schema: authSchema)

        // Encode challenge as base64
        let base64Challenge = challenge.base64EncodedString()
        let encoded = base64Challenge.data(using: .utf8)!

        let valid = try wallet.validateData(data: encoded, metadata: metadata)
        XCTAssertTrue(valid)

        let signature = try wallet.sign(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0,
            message: encoded
        )

        XCTAssertEqual(signature.count, 64)

        let publicKey = try wallet.keyGen(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0
        )

        let isValid = wallet.verifyWithPublicKey(
            signature: signature,
            message: encoded,
            publicKey: publicKey
        )

        XCTAssertTrue(isValid)
    }

    func testSignAuthenticationChallenge32BytesMsgpack() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        // Generate 32 random bytes for authentication challenge
        let challenge = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })

        // Read auth schema file for authentication. 32 bytes challenge to sign
        let authSchema = try Schema(filePath: "Tests/x-hd-wallet-apiTests/schemas/auth.request.json")
        let metadata = SignMetadata(encoding: .msgpack, schema: authSchema)

        // Encode challenge as msgpack
        let encoded = MessagePack.pack(MessagePackValue.binary(challenge))

        let valid = try wallet.validateData(data: encoded, metadata: metadata)
        XCTAssertTrue(valid)

        let signature = try wallet.sign(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0,
            message: encoded
        )

        XCTAssertEqual(signature.count, 64)

        let publicKey = try wallet.keyGen(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0
        )

        let isValid = wallet.verifyWithPublicKey(
            signature: signature,
            message: encoded,
            publicKey: publicKey
        )

        XCTAssertTrue(isValid)
    }

    func testSignAuthenticationChallenge32BytesNoEncoding() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        // Generate 32 random bytes for authentication challenge
        let challenge = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })

        // Read auth schema file for authentication. 32 bytes challenge to sign
        let authSchema = try Schema(filePath: "Tests/x-hd-wallet-apiTests/schemas/auth.request.json")
        let metadata = SignMetadata(encoding: .none, schema: authSchema)

        let valid = try wallet.validateData(data: challenge, metadata: metadata)
        XCTAssertTrue(valid)

        let signature = try wallet.sign(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0,
            message: challenge
        )

        XCTAssertEqual(signature.count, 64)

        let publicKey = try wallet.keyGen(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0
        )

        let isValid = wallet.verifyWithPublicKey(
            signature: signature,
            message: challenge,
            publicKey: publicKey
        )

        XCTAssertTrue(isValid)
    }

    func testSignArbitraryMessageBase64() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        let message = ["letter": "Hello World"]
        let messageData = try JSONSerialization.data(withJSONObject: message, options: [])
        let base64Message = messageData.base64EncodedString()
        let encoded = base64Message.data(using: .utf8)!

        // Schema of what we are signing
        let jsonSchema: [String: Any] = [
            "type": "object",
            "properties": [
                "letter": ["type": "string"]
            ]
        ]

        let schema = try createMockSchema(jsonSchema: jsonSchema)
        let metadata = SignMetadata(encoding: .base64, schema: schema)

        let signature = try wallet.signData(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0,
            data: encoded,
            metadata: metadata
        )

        XCTAssertEqual(signature.count, 64)

        let publicKey = try wallet.keyGen(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0
        )

        let isValid = wallet.verifyWithPublicKey(
            signature: signature,
            message: encoded,
            publicKey: publicKey
        )

        XCTAssertTrue(isValid)
    }

    func testSignArbitraryMessageMsgpack() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        let messagePackValue = MessagePackValue.map([
            MessagePackValue.string("letter"): MessagePackValue.string("Hello World")
        ])
        let encoded = MessagePack.pack(messagePackValue)

        // Schema of what we are signing
        let jsonSchema: [String: Any] = [
            "type": "object",
            "properties": [
                "letter": ["type": "string"]
            ]
        ]

        let schema = try createMockSchema(jsonSchema: jsonSchema)
        let metadata = SignMetadata(encoding: .msgpack, schema: schema)

        let signature = try wallet.signData(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0,
            data: encoded,
            metadata: metadata
        )

        XCTAssertEqual(signature.count, 64)

        let publicKey = try wallet.keyGen(
            context: .Address,
            account: 0,
            change: 0,
            keyIndex: 0
        )

        let isValid = wallet.verifyWithPublicKey(
            signature: signature,
            message: encoded,
            publicKey: publicKey
        )

        XCTAssertTrue(isValid)
    }

    func testSigningFailsWithInvalidSchemaBase64() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        let message = ["letter": "Hello World"]
        let messageData = try JSONSerialization.data(withJSONObject: message, options: [])
        let base64Message = messageData.base64EncodedString()
        let encoded = base64Message.data(using: .utf8)!

        // Wrong schema - expecting string but sending object
        let jsonSchema: [String: Any] = [
            "type": "string"
        ]

        let schema = try createMockSchema(jsonSchema: jsonSchema)
        let metadata = SignMetadata(encoding: .base64, schema: schema)

        XCTAssertThrowsError(try wallet.signData(
            context: .Identity,
            account: 0,
            change: 0,
            keyIndex: 0,
            data: encoded,
            metadata: metadata
        ))
    }

    func testSigningFailsWithInvalidSchemaMsgpack() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        let messagePackValue = MessagePackValue.map([
            MessagePackValue.string("letter"): MessagePackValue.string("Hello World")
        ])
        let encoded = MessagePack.pack(messagePackValue)

        // Wrong schema - expecting string but sending object
        let jsonSchema: [String: Any] = [
            "type": "string"
        ]

        let schema = try createMockSchema(jsonSchema: jsonSchema)
        let metadata = SignMetadata(encoding: .msgpack, schema: schema)

        XCTAssertThrowsError(try wallet.signData(
            context: .Identity,
            account: 0,
            change: 0,
            keyIndex: 0,
            data: encoded,
            metadata: metadata
        ))
    }

    func testRejectTXTag() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        // Create data with TX tag prefix
        let randomData = Data((0 ..< 64).map { _ in UInt8.random(in: 0 ... 255) })
        let messagePackValue = MessagePackValue.binary(randomData)
        let packedData = MessagePack.pack(messagePackValue)
        var transaction = Data("TX".utf8)
        transaction.append(packedData)

        let schema = try createMockSchema(jsonSchema: [:])
        let metadata = SignMetadata(encoding: .msgpack, schema: schema)

        XCTAssertThrowsError(try wallet.signData(
            context: .Identity,
            account: 0,
            change: 0,
            keyIndex: 0,
            data: transaction,
            metadata: metadata
        ))
    }

    func testRejectMXTag() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        // Create data with MX tag prefix
        let randomData = Data((0 ..< 64).map { _ in UInt8.random(in: 0 ... 255) })
        let messagePackValue = MessagePackValue.binary(randomData)
        let packedData = MessagePack.pack(messagePackValue)
        var transaction = Data("MX".utf8)
        transaction.append(packedData)

        let schema = try createMockSchema(jsonSchema: [:])
        let metadata = SignMetadata(encoding: .msgpack, schema: schema)

        XCTAssertThrowsError(try wallet.signData(
            context: .Identity,
            account: 0,
            change: 0,
            keyIndex: 0,
            data: transaction,
            metadata: metadata
        ))
    }

    func testRejectProgramTag() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        // Create data with Program tag prefix
        let randomData = Data((0 ..< 64).map { _ in UInt8.random(in: 0 ... 255) })
        let messagePackValue = MessagePackValue.binary(randomData)
        let packedData = MessagePack.pack(messagePackValue)
        var transaction = Data("Program".utf8)
        transaction.append(packedData)

        let schema = try createMockSchema(jsonSchema: [:])
        let metadata = SignMetadata(encoding: .msgpack, schema: schema)

        XCTAssertThrowsError(try wallet.signData(
            context: .Identity,
            account: 0,
            change: 0,
            keyIndex: 0,
            data: transaction,
            metadata: metadata
        ))
    }

    func testRejectProgDataTag() throws {
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let wallet = XHDWalletAPI(seed: seed)!

        // Create data with ProgData tag prefix
        let randomData = Data((0 ..< 64).map { _ in UInt8.random(in: 0 ... 255) })
        let messagePackValue = MessagePackValue.binary(randomData)
        let packedData = MessagePack.pack(messagePackValue)
        var transaction = Data("ProgData".utf8)
        transaction.append(packedData)

        let schema = try createMockSchema(jsonSchema: [:])
        let metadata = SignMetadata(encoding: .msgpack, schema: schema)

        XCTAssertThrowsError(try wallet.signData(
            context: .Identity,
            account: 0,
            change: 0,
            keyIndex: 0,
            data: transaction,
            metadata: metadata
        ))
    }

    func testSchema() throws {
        // Should successfully load
        _ = try Schema(filePath: String("Tests/x-hd-wallet-apiTests/schemas/auth.request.json"))
        _ = try Schema(filePath: String("Tests/x-hd-wallet-apiTests/schemas/msg.schema.json"))

        // Malformed schema
        XCTAssertThrowsError(try Schema(filePath: String("Tests/x-hd-wallet-apiTests/schemas/malformed.json")))
        XCTAssertThrowsError(try Schema(filePath: String("/path/that/does/not/exist.json")))
    }

    func testECDH() throws {
        let aliceSeed = try Mnemonic.deterministicSeedString(from: "exact remain north lesson program series excess lava material second riot error boss planet brick rotate scrap army riot banner adult fashion casino bamboo")
        let alice = XHDWalletAPI(seed: aliceSeed)
        guard alice != nil else {
            throw NSError(domain: "XHDWalletAPIECDHTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "XHDWalletAPI not initialized"])
        }

        let bobSeed = try Mnemonic.deterministicSeedString(from: "identify length ranch make silver fog much puzzle borrow relax occur drum blue oval book pledge reunion coral grace lamp recall fever route carbon")
        let bob = XHDWalletAPI(seed: bobSeed)
        guard bob != nil else {
            throw NSError(domain: "XHDWalletAPIECDHTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "XHDWalletAPI not initialized"])
        }

        let aliceKey = try alice?.keyGen(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0, derivationType: BIP32DerivationType.Khovratovich)
        let bobKey = try bob?.keyGen(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0, derivationType: BIP32DerivationType.Khovratovich)

        let aliceSharedSecret = try alice?.ECDH(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0, otherPartyPub: bobKey!, meFirst: true, derivationType: BIP32DerivationType.Khovratovich)
        let bobSharedSecret = try bob?.ECDH(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0, otherPartyPub: aliceKey!, meFirst: false, derivationType: BIP32DerivationType.Khovratovich)

        XCTAssertNotEqual(aliceKey, bobKey)
        XCTAssertEqual(aliceSharedSecret, bobSharedSecret)
        XCTAssertEqual(aliceSharedSecret, Data([202, 114, 20, 173, 185, 153, 18, 48, 253, 145, 160, 157, 145, 158, 198, 130, 178, 172, 151, 129, 183, 110, 32, 107, 75, 135, 244, 221, 110, 246, 66, 127]))

        // Reverse concatenation order

        let aliceSharedSecret2 = try alice?.ECDH(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0, otherPartyPub: bobKey!, meFirst: false, derivationType: BIP32DerivationType.Khovratovich)
        let bobSharedSecret2 = try bob?.ECDH(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0, otherPartyPub: aliceKey!, meFirst: true, derivationType: BIP32DerivationType.Khovratovich)

        XCTAssertNotEqual(aliceSharedSecret, aliceSharedSecret2)
        XCTAssertNotEqual(bobSharedSecret, bobSharedSecret2)
        XCTAssertEqual(aliceSharedSecret2, bobSharedSecret2)
        XCTAssertEqual(aliceSharedSecret2, Data([90, 215, 114, 148, 204, 139, 215, 147, 233, 41, 219, 196, 163, 237, 229, 68, 134, 255, 92, 129, 181, 253, 137, 142, 191, 244, 101, 46, 252, 253, 250, 26]))

        // Encrypt/Decrypt with shared secret
        let message = "Hello, World!"
        let nonce = Data([16, 197, 142, 8, 174, 91, 118, 244, 202, 136, 43, 200, 97, 242, 104, 99, 42, 154, 191, 32, 67, 30, 6, 123])
        let ciphertext = TestUtils.cryptoSecretBoxEasy(cleartext: message, nonce: nonce, symmetricKey: aliceSharedSecret!)
        XCTAssertEqual(ciphertext, Data(hexString: "FB07303A391687989674F28A1A9B88FCA3D107227D87DADE662DFA3722"))
        XCTAssertEqual(ciphertext, Data([251, 7, 48, 58, 57, 22, 135, 152, 150, 116, 242, 138, 26, 155, 136, 252, 163, 209, 7, 34, 125, 135, 218, 222, 102, 45, 250, 55, 34]))

        let cleartext = TestUtils.cryptoSecretBoxOpenEasy(ciphertext: ciphertext, nonce: nonce, symmetricKey: aliceSharedSecret!)
        XCTAssertEqual(cleartext, message)
    }
}

class DataExtensionTests: XCTestCase {
    func testHexStringInit() {
        // Test with valid hex string
        let hexString = "48656c6c6f" // "Hello" in ASCII
        let data = Data(hexString: hexString)
        XCTAssertEqual(data, "Hello".data(using: .utf8))

        // Test with invalid hex string
        let invalidHexString = "GGGG"
        let invalidData = Data(hexString: invalidHexString)
        XCTAssertNil(invalidData)

        // Test with empty string
        let emptyString = ""
        let emptyData = Data(hexString: emptyString)
        XCTAssertEqual(emptyData, Data())
    }
}
