# Quorum Account Keypair Generator

Simple javascript utility to generate [Quorum](https://github.com/jpmorganchase/quorum) / [Ethereum](https://github.com/ethereum/go-ethereum) key pair JSON's

Implements Version 3 of the Web3 secret storage spec

## Usage

Install : `npm install --save quorum-keygen`

```
var quorumKeyGen = require('quorum-keygen');

let quorumKeyPair = quorumKeyGen.newAccount('Pass phrase goes here');

```

### Output :

```
{
  "address": "eee9b1362a6eee608d56538bd619ba4e9c525022",
  "crypto": {
    "cipher": "aes-128-ctr",
    "ciphertext": "ea7ca8fd9965f1621918ee4875cb3572e11c049014ff34b3e67c3c09ea 6ff8bf",
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

## Acknowledgements

This utility was made possible by the amazing contributions by below libraries and their authors

1. [secp256k1](https://www.npmjs.com/package/secp256k1)
2. [keccak](https://www.npmjs.com/package/keccak)
3. [uuid](https://www.npmjs.com/package/uuid)