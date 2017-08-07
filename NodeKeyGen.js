/* +--------------------------------------------------------------+
 *  Quorum / Ethereum Node Keypair Generator v1.0
 *  Author : Ashfaq Ahmed S [https://github.com/broadridge-labs]
 * +--------------------------------------------------------------+*/
var secp256k1   = require('secp256k1');
var crypto      = require('crypto');

/**
 * Generates nodekeys for quorum/ethereum nodes
 * +- Can generate a public key from an existing private key (HEX)
 * @return {Object}
 */
exports.generateNodeKeys = (privateKeyHex) => {

    let privateKeyBuf = null;
    if(privateKeyHex != undefined){
        console.log('+- Operating on provided private key (hex)');
        privateKeyBuf = new Buffer(privateKeyHex, 'hex');
    } else {
        console.log('+- Generating private key');
        privateKeyBuf = _generatePrivateKey();
    }

    // Generate public key
    console.log('+- Generating public key');
    let publicKeyBuf = _generatePublicKey(privateKeyBuf);

    console.log('+- Key pair generation completed');
    /** Return key pair to caller */
    return {
        "privateKey"    : privateKeyBuf.toString('hex'),
        "publicKey"     : publicKeyBuf.toString('hex')
    }
    
}

/**
 * Generates 256 bit randomness
 * @return {Buffer}
 */
_generatePrivateKey = () => {
    return new Buffer(crypto.randomBytes(32), 'hex');
}

/**
 * Generates 512 bit secp256k1 public key
 * @return {Buffer}
 */
_generatePublicKey = (privateKeyBuf) => {
    return secp256k1.publicKeyCreate(privateKeyBuf, false).slice(1);
}

