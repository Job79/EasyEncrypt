<p align="center">
  <b>EasyEncrypt</b>
  <br/>
  <img src="https://img.shields.io/badge/License-MIT-green.svg">
  <img src="https://img.shields.io/badge/version-1.0.3.1-green.svg">
  <img src="https://img.shields.io/badge/build-passing-green.svg">
  <br/>
  <br/>
  <a>Library that makes encrypting strings, byte arrays and files easy. Supports Aes, TripleDES, (.net framework only, Des, RC2 and Rijndael)<a/>
  <br/><br/>
</p>

```cs
encryptedString = new Encryption(Aes.Create(), Password, Salt).Encrypt(Input);
decryptedString = new Encryption(Aes.Create(), Password, Salt).Decrypt(EnryptedInput);

encryptedString = new Encryption(TripleDES.Create(), Password, Salt).Encrypt(Input);
decryptedString = new Encryption(TripleDES.Create(), Password, Salt).Decrypt(EnryptedInput);

encryptedString = new Encryption(DES.Create(), Password, Salt).Encrypt(Input);
decryptedString = new Encryption(DES.Create(), Password, Salt).Decrypt(EnryptedInput);

encryptedString = new Encryption(RC2.Create(), Password, Salt).Encrypt(Input);
decryptedString = new Encryption(RC2.Create(), Password, Salt).Decrypt(EnryptedInput);

encryptedString = new Encryption(Rijndael.Create(), Password, Salt).Encrypt(Input);
decryptedString = new Encryption(Rijndael.Create(), Password, Salt).Decrypt(EnryptedInput);
```
# [Documentation](https://github.com/GHenkje/EasyEncrypt/wiki)
