import Foundation
import CryptoKit

class CryptAES{
    
    var key = SymmetricKey(size: .bits256)
    
    init(){
        getRandomKey()
    }
    init(_ key: String) {
        getKey(passwordStr: key)
    }
    func getKey(passwordStr: String){
        let password = passwordStr.data(using: .utf8)!
        let hash = self.hashSHA256fromData(data: password)
        self.key = SymmetricKey(data: hash)
    }
    func getRandomKey(){
        self.key = SymmetricKey(size: .bits256)
    }
    func encryptString(stringData: String) -> AES.GCM.SealedBox {
        let data = try! stringData.data(using: .utf8)!
        let sealedBox = try! AES.GCM.seal(data, using: self.key)
        return sealedBox
    }
    func encryptData(data: Data) -> AES.GCM.SealedBox{
        let sealedBox = try! AES.GCM.seal(data, using: self.key, nonce: AES.GCM.Nonce())
        return sealedBox
    }
    func decryptData(sealedBox: AES.GCM.SealedBox) -> Data{
        let sealedBoxRestored = try! AES.GCM.SealedBox(nonce: sealedBox.nonce, ciphertext: sealedBox.ciphertext, tag: sealedBox.tag)
        let decryptedData = try! AES.GCM.open(sealedBoxRestored, using: key)
        return decryptedData
    }
    func HashSHA256fromString(string: String) -> String{
        let data = Data(string.utf8)
        let digest = SHA256.hash(data: data)
        let hash = digest.compactMap{ String(format: "%02x", $0) }.joined()
        print(hash)
        return hash
    }
    func hashSHA256fromData(data: Data) -> Data{
        let digest = SHA256.hash(data: data)
        return Data(digest.makeIterator())
    }
    func SHA256DigestToHex(digest: SHA256Digest) -> String{
        return digest.compactMap{ String(format: "%02x", $0) }.joined()
    }
}
