/*
 * +--------------------------------------------------------------+
 *  Quorum Account Creator v1.0
 *  Author : Ashfaq Ahmed S [https://github.com/0yukikaze0]
 * +--------------------------------------------------------------+
 */
var secp256k1   = require('secp256k1');
var keccak      = require('keccak')
var crypto      = require('crypto');
var uuid        = require('uuid/v4');
/**
 * Creates a Quorum account
 * @param {string} passPhrase to the lock the private key
 * @return {Object}
 */
exports.createNewAccount = function(passPhrase){

    /**
     * +--------------------------------+
     * | Key pair creation              |
     * +--------------------------------+
     * Implements version 3 of ethereum secret storage
     * 
     * [1] -> Create a private key from a buffer of 256 bit randombytes
     * [2] -> Extract a secp256k1 public key from [1]
     * [3] -> Convert [2] => Hexadecimal public key (address)
     *                          |
     *                          +- Lower 160bits of Keccak SHA3 hash
     */
    // [1]
    let privateKeyBuf = new Buffer(crypto.randomBytes(32), 'hex');
    // [2]
    let publicKeyBuf = secp256k1.publicKeyCreate(new Buffer(privateKeyBuf), false).slice(1);
    // [3]
    let address = keccak('keccak256').update(publicKeyBuf).digest().slice(-20).toString('hex')
    
    /**
     * +--------------------------------+
     * | Encryption                     |
     * +--------------------------------+
     * Crypto algorithm : aes-128-ctr
     * MAC : SHA3 (keccak-256)[sha3] 
     * Key Derivation function : pbkdf2
     * 
     * [1] Generate 32 byte salt
     * [2] Derive 32 byte encryption key
     *      -> Apply pbkdf2 on passPhrase
     *      +- prf = hmac-sha256
     *      +- Iterations (c) = 262144
     * [3] Encrypt
     */
    // [1]
    let salt = crypto.randomBytes(32).toString('hex');
    // [2]
    let kdf = deriveKey(passPhrase, salt)
    // [3]
    let cipherObj = createCipherText(kdf['dk'], crypto.randomBytes(16), privateKeyBuf);

    /**
     * Build JSON datastructure and return to caller
     */
    return {
                "address": address,
                "crypto":   {
                                "cipher": cipherObj['cipher'],
                                "ciphertext": cipherObj['ciphertext'],
                                "cipherparams": cipherObj['cipherparams'],
                                "kdf": kdf['kdf'],
                                "kdfparams": kdf['kdfparams'],
                                "mac": cipherObj['mac']
                            },
                "id": uuid(),
                "version": 3
            }
}

deriveKey = function(passPhrase, salt){
    let derivedKey = crypto.pbkdf2Sync(passPhrase,new Buffer(salt,'hex'), 262144, 32, 'sha256');
    return {
        "kdf" : "pbkdf2",
        "dk" : derivedKey.toString('hex'),
        "kdfparams" : {
            "c" : 262144,
            "dklen" : 32,
            "prf" : "hmac-sha256",
            "salt" : salt
        }
    }
}

createCipherText = function(derivedKey, ivBuf, operand){

    // Cipher key = Highest 16 bytes of derived key
    let cipherKeyBuf = new Buffer(derivedKey,'hex').slice(0,16);
    let cipher = crypto.createCipheriv('aes-128-ctr',cipherKeyBuf,ivBuf)
    let cipherText = cipher.update(operand,'utf8','hex');
    cipherText += cipher.final('hex');

    /**
     * MAC = keccak256( concat(<second highest 16 bytes> + ciphertext) )
     */
    let mac = createMAC(derivedKey, cipherText)

    return {
        "cipher" : "aes-128-ctr",
        "cipherparams" : {
            "iv" : ivBuf.toString('hex')
        },
        "ciphertext" : cipherText,
        "mac" : mac.toString('hex')
    }

}

createMAC = function(derivedKey, cipherText){

    let derivedKeyBuf = new Buffer(derivedKey,'hex').slice(16,32);
    let cipherTextBuf = new Buffer(cipherText,'hex');
    
    return keccak('keccak256')
            .update(Buffer.concat([derivedKeyBuf, cipherTextBuf], derivedKeyBuf.length + cipherTextBuf.length))
            .digest();
}

exports.testVector = function(){

    let salt = 'ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd';
    let passPhrase = 'testpassword'

    let derivedKey = deriveKey(passPhrase, salt);
    console.log('Derived key : ' + JSON.stringify(derivedKey))

    let cipherObj = createCipherText(derivedKey['dk'].toString('hex'), new Buffer('6087dab2f9fdbbfaddc31a909735c1e6','hex'), new Buffer('7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d','hex'));

    console.log('Cipher : ' + JSON.stringify(cipherObj))
}

