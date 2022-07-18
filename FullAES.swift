import Foundation
import CryptoKit

class CryptoManager{
    
    var key: SymmetricKey = SymmetricKey(size: .bits256)
    let sold: String = "Very long string... "
    
    init(){
        setRandomKey()
        
    }
    init(keyStr: String) {
        setKey(passwordStr: keyStr)
    }
    init(keyHash: Data){
        self.key = SymmetricKey(data: keyHash)
    }
    init(summetricKey: SymmetricKey){
        self.key = summetricKey
    }
    func changeKey(passwordStr: String) -> Bool{
        let password = passwordStr.data(using: .utf8)!
        let hash = self.hashSHA256fromData(data: password)
        let key = SymmetricKey(data: hash)
        if self.key == key{
            self.key = key
            return true
        } else {
            return false
        }
    }
    func eqKey(passwordStr: String) -> Bool{
        let password = passwordStr.data(using: .utf8)!
        let hash = self.hashSHA256fromData(data: password)
        let key = SymmetricKey(data: hash)
        if self.key == key{
            return true
        } else {
            return false
        }
    }
    func eqKey(passwordHash: Data) -> Bool{
        let key = SymmetricKey(data: passwordHash)
        if self.key == key{
            return true
        } else {
            return false
        }
    }
    func setKey(data: Data){
        self.key = SymmetricKey(data: data)
    }
    func setKey(passwordStr: String){
        let password = passwordStr.data(using: .utf8)!
        let hash = self.hashSHA256fromData(data: password)
        self.key = SymmetricKey(data: hash)
    }
    func getKey(passwordStr: String) -> Data{
        let password = passwordStr.data(using: .utf8)!
        let hash = self.hashSHA256fromData(data: password)
        return hash
    }
    func setRandomKey(){
        self.key = SymmetricKey(size: .bits256)
    }
    func encryptString(stringData: String) -> AES.GCM.SealedBox {
        let data = stringData.data(using: .utf8)!
        let sealedBox = try! AES.GCM.seal(data, using: self.key)
        return sealedBox
    }
    func encryptData(data: Data) -> Data?{
        print(self.key)
        let sealedBox = try! AES.GCM.seal(data, using: self.key, nonce: AES.GCM.Nonce())
        return sealedBox.combined
    }
    func decryptData(data: Data) throws -> Data?{
        let sealedBox = try! AES.GCM.SealedBox(combined: data)
        let decryptedData = try? AES.GCM.open(sealedBox, using: self.key)
        return decryptedData
    }
    func encryptSealBox(data: Data) -> AES.GCM.SealedBox{
        let sealedBox = try! AES.GCM.seal(data, using: self.key, nonce: AES.GCM.Nonce())
        return sealedBox
    }
    func decryptSealBox(sealedBox: AES.GCM.SealedBox) -> Data{
        let sealedBoxRestored = try! AES.GCM.SealedBox(nonce: sealedBox.nonce, ciphertext: sealedBox.ciphertext, tag: sealedBox.tag)
        let decryptedData = try! AES.GCM.open(sealedBoxRestored, using: key)
        return decryptedData
    }
    func HashSHA256fromString(string: String) -> String{
        let data = Data(salty(password: string).utf8)
        let digest = SHA256.hash(data: data)
        let hash = digest.compactMap{ String(format: "%02x", $0) }.joined()
        return hash
    }
    func hashSHA256fromData(data: Data) -> Data{
        let digest = SHA256.hash(data: salty(data: data))
        return Data(digest.makeIterator())
    }
    func SHA256DigestToHex(digest: SHA256Digest) -> String{
        return digest.compactMap{ String(format: "%02x", $0) }.joined()
    }
    func salty(data: Data) -> Data{
        return data + self.sold.data(using: .utf8)!
    }
    func salty(password: String) -> String{
        return password + self.sold
    }
}
