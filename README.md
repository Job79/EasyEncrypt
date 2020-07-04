<p align="center">
  <b>EasyEncrypt</b>
  <br/>
  <img src="https://img.shields.io/badge/License-MIT-green.svg">
  <img src="https://img.shields.io/badge/version-2.2.1.0-green.svg">
  <img src="https://img.shields.io/badge/build-passing-green.svg">
  <br/>
  <br/>
  <a>Wrapper around the SymmetricAlgorithm class that makes encrypting strings, arrays, streams and files simple<a/>
  <br/><br/>
</p>
  
```cs
// Create encrypter with default algorithm (AES) and generate a new random key
var encrypter = new EasyEncrypt();
            
// Encrypt and decrypt a string
var encryptedString = encrypter.Encrypt("Example data");
var decryptedString = encrypter.Decrypt(encryptedString);

//! See EasyEncrypt.Examples for more 
```

