"use strict";

var chai    = require('chai');
var should  = chai.should();

var quorumKeygen = require('./index');

/*-----------------------------------------------------------------------*
 * Test Vectors 
 *-----------------------------------------------------------------------*/
 let passPhrase     =   'testpassword';
 let secret         =   '7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d';
 let inputVector    =   '6087dab2f9fdbbfaddc31a909735c1e6';
 let salt           =   'ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd';
/*-----------------------------------------------------------------------*/

/*-----------------------------------------------------------------------*
 * Expected Result 
 *-----------------------------------------------------------------------*/
 let derivedKey = 'f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551';
 let cipherText = '5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46';
 let mac        = '517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2'
/*-----------------------------------------------------------------------*/


describe('From Test Vectors', () => {
    let result = quorumKeygen.runTests(passPhrase, secret, salt, inputVector);
    describe('Key Derivation',() => {
        it(`Derived key should match ${derivedKey}`, () => {
            result.kdf.dk.should.equal(derivedKey);
        })    
    });

    describe('Cipher', () => {
        it(`Cipher text should match ${cipherText} ` , () => {
            result.cipher.ciphertext.should.equal(cipherText);
        })
    })

    describe('Message Authentication Code' , () => {
        it(`MAC should equal ${mac}`, () => {
            result.mac.should.equal(mac);
        })
    })
})


describe('New key pair generation' ,  () => {
    let keypair = quorumKeygen.createNewAccount(passPhrase);
    describe('Integrity', () => {
        it('Result should be a well formed JSON', () => {
            keypair.should.be.a('object');
        })

        it('Address, Crypto, Id and version are populated' , () => {
            keypair.should.have.all.keys('address','crypto','id','version');
        })

        it('MAC should be a 32 byte string' , () => {
            keypair.crypto.mac.should.have.lengthOf(64);
        })
    })
    
    describe('Key derivation function', () => {
        it('KDF parameters are populated' , () => {
            keypair.crypto.kdfparams.should.have.all.keys(['c','dklen','prf','salt'])
        });
    })

    describe('Cipher', () => {
        it('Input vector is populated', () => {
            keypair.crypto.cipherparams.should.have.all.keys(['iv'])
        })
    })
    
})
