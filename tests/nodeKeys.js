'use strict'

var chai = require('chai');
var should = chai.should();

var quorumNodeKeys = require('../index');

/*--------------------------------------------------------------*
 * Test Vectors
 *--------------------------------------------------------------*/
let privateKeyHex = '77bd02ffa26e3fb8f324bda24ae588066f1873d95680104de5bc2db9e7b2e510';
/*--------------------------------------------------------------*/

/*--------------------------------------------------------------*
 * Expected results
 *--------------------------------------------------------------*/
let publicKeyHex        = '61077a284f5ba7607ab04f33cfde2750d659ad9af962516e159cf6ce708646066cd927a900944ce393b98b95c914e4d6c54b099f568342647a1cd4a262cc0423';
let privateHexKeySize   = 64;
let publicHexKeySize    = 128;
/*--------------------------------------------------------------*/

describe('Testing dynamic node key generation', () => {
    let result = quorumNodeKeys.generateNodeKeys();
    it('Result should be wellformed JSON', () => {
        result.should.be.a('object');
    })
    it(`Private key size - ${privateHexKeySize/2} bytes`, () => {
        result.privateKey.should.have.lengthOf(privateHexKeySize);
    })
    it(`Public key size - ${publicHexKeySize/2} bytes`, () => {
        result.publicKey.should.have.lengthOf(publicHexKeySize);
    })
});

describe('Testing public key generation from test vector', () => {
    let result = quorumNodeKeys.generateNodeKeys(privateKeyHex);
    it('Public key validation', () => {
        result.publicKey.should.equal(publicKeyHex);
    })
});