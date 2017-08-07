/*
 * +--------------------------------------------------------------+
 *  Quorum Account Creator v1.0
<<<<<<< HEAD
 *  Author : Ashfaq Ahmed S [https://github.com/broadridge-labs]
=======
 *  Author : Ashfaq Ahmed S [https://github.com/0yukikaze0]
>>>>>>> 7563f6371299e5a3f6941d823f01ba86fe756d9c
 * +--------------------------------------------------------------+
 */
var secp256k1   = require('secp256k1');
var keccak      = require('keccak')
var crypto      = require('crypto');
var uuid        = require('uuid/v4');
<<<<<<< HEAD
var nodeKeyGen  = require('./NodeKeyGen');

/**
 * Creates a Quorum / Ethereum node key pair
 * +- Can generate a public key from existing private key (HEX)
 */
exports.generateNodeKeys = (privateKeyHex) => {    
    return nodeKeyGen.generateNodeKeys(privateKeyHex);
}
=======
>>>>>>> 7563f6371299e5a3f6941d823f01ba86fe756d9c
/**
 * Creates a Quorum account
 * @param {string} passPhrase to the lock the private key
 * @return {Object}
 */
<<<<<<< HEAD
exports.createNewAccount = (passPhrase) => {
=======
exports.createNewAccount = function(passPhrase){
>>>>>>> 7563f6371299e5a3f6941d823f01ba86fe756d9c

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

<<<<<<< HEAD
deriveKey = (passPhrase, salt) => {
=======
deriveKey = function(passPhrase, salt){
>>>>>>> 7563f6371299e5a3f6941d823f01ba86fe756d9c
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

<<<<<<< HEAD
createCipherText = (derivedKey, ivBuf, operand) => {
=======
createCipherText = function(derivedKey, ivBuf, operand){
>>>>>>> 7563f6371299e5a3f6941d823f01ba86fe756d9c
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

<<<<<<< HEAD
createMAC = (derivedKey, cipherText) => {
=======
createMAC = function(derivedKey, cipherText){
>>>>>>> 7563f6371299e5a3f6941d823f01ba86fe756d9c

    let derivedKeyBuf = new Buffer(derivedKey,'hex').slice(16,32);
    let cipherTextBuf = new Buffer(cipherText,'hex');
    
    return keccak('keccak256')
            .update(Buffer.concat([derivedKeyBuf, cipherTextBuf], derivedKeyBuf.length + cipherTextBuf.length))
            .digest();
}

<<<<<<< HEAD
exports.runTests = (passphrase, secret, salt, iv) => {
=======
exports.runTests = function(passphrase, secret, salt, iv){
>>>>>>> 7563f6371299e5a3f6941d823f01ba86fe756d9c

    let kdf     = deriveKey(passphrase, salt);
    let cipher  = createCipherText(kdf.dk, new Buffer(iv, 'hex'), new Buffer(secret,'hex'));    
    let mac     = createMAC(kdf['dk'], cipher['ciphertext']);

    return {
        kdf     : kdf,
        cipher  : cipher,
        mac     : mac.toString('hex')
    }

}