# Quorum Account Keypair Generator

Simple javascript utility to generate
1.  [Quorum](https://github.com/jpmorganchase/quorum) / [Ethereum](https://github.com/ethereum/go-ethereum) account key pair JSON's
2. [Quorum](https://github.com/jpmorganchase/quorum) / [Ethereum](https://github.com/ethereum/go-ethereum) Node key pairs

Implements Version 3 of the Web3 secret storage spec

## Usage

Install : `npm install --save quorum-keygen`

### Quorum / Ethereum account generation
```
var quorumKeyGen = require('quorum-keygen');

let quorumKeyPair = quorumKeyGen.newAccount('Pass phrase goes here');

```

Output :

```
{
  "address": "eee9b1362a6eee608d56538bd619ba4e9c525022",
  "crypto": {
    "cipher": "aes-128-ctr",
    "ciphertext": "ea7ca8fd9965f1621918ee4875cb3572e11c049014ff34b3e67c3c09ea6ff8bf",
    "cipherparams": {
      "iv": "5c6ff4dbc9dda4b33e74e02c9f99dcd0"
    },
    "kdf": "pbkdf2",
    "kdfparams": {
      "c": 262144,
      "dklen": 32,
      "prf": "hmac-sha256",
      "salt": "38be5505b42344de6426e918442e2e5f1f48b543f74d36640ecabf5f506151fb"
    },
    "mac": "7f4843064ba4424b5385da19c08d7e29ac80ff6b067a1149cdfef8c5e4aeab0e"
  },
  "id": "127587ad-077b-4835-9643-3094702ece74",
  "version": 3
}
```
### Quorum / Ethereum node key pair generation
```

var quorumKeyGen = require('quorum-keygen');

let nodeKeyPair = quorumKeyGen.generateNodeKeys();

// OR generate public key from a private key in hex

let nodeKeyPair = quorumKeyGen.generateNodeKeys('77bd02ffa26e3fb8f324bda24ae588066f1873d95680104de5bc2db9e7b2e510');

```

Output :

```
{
  "privateKey" : "77bd02ffa26e3fb8f324bda24ae588066f1873d95680104de5bc2db9e7b2e510",
  "publicKey" : "61077a284f5ba7607ab04f33cfde2750d659ad9af962516e159cf6ce708646066cd927a900944ce393b98b95c914e4d6c54b099f568342647a1cd4a262cc0423"
}
```
## Acknowledgements

This utility was made possible by the amazing contributions by below libraries and their authors

1. [secp256k1](https://www.npmjs.com/package/secp256k1)
2. [keccak](https://www.npmjs.com/package/keccak)
3. [uuid](https://www.npmjs.com/package/uuid)