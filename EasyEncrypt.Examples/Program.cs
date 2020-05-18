using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EasyEncrypt.Examples
{
    class Program
    {
        static void Main(string[] args)
        {
            /*                 Readme examples            */

            // Create encrypter with default algorithm (AES) and generate a new random key
            var encrypter = new EasyEncrypt();
            
            // Encrypt and decrypt a string
            var encryptedString = encrypter.Encrypt("Example data");
            var decryptedString = encrypter.Decrypt(encryptedString);

            /*                 AES encryption            */

            // Get key from encrypter
            byte[] key = encrypter.GetKey();

            // Create encrypter with default algorithm (AES) and use an existing key
            using var encrypterWithKey = new EasyEncrypt(key: key);

            // Create encrypter with default algorithm (AES) and create encryption key from password and salt (with PBKDF2)
            using var encrypterWithPassword = new EasyEncrypt("Password", "Salt12345678");

            // Encrypt and decrypt a byte[]
            var encryptedArray = encrypter.Encrypt(Encoding.UTF8.GetBytes("Example data"));
            var decryptedArray = encrypter.Decrypt(encryptedArray);

            /*                 Custom algorithms encryption            */

            // Create encrypter with DES encryption
            using var DESencrypter = new EasyEncrypt(DES.Create());

            // Create encryptor with TripleDES encryption and create encryption key from password and salt (with PBKDF2)
            using var tripleDeSencrypter = new EasyEncrypt("Password", "Salt12345678", TripleDES.Create());

            /*                Encrypting streams            */

            // Readable input stream, gets disposed when encrypted
            using var inputStream = new MemoryStream(Encoding.UTF8.GetBytes("Example data"));
            // Writable output stream, encrypted data gets written to this stream 
            using var encryptedStream = new MemoryStream();
            // Encrypt our stream
            encrypter.EncryptStream(inputStream, encryptedStream);

            // Writable output stream, decrypted data gets written to this stream
            using var decryptedStream = new MemoryStream();
            // Decrypt our stream, encrypted data gets disposed
            encrypter.DecryptStream(encryptedStream, decryptedStream);

            /*            Encrypting files        */
            const string inputFile = "Data.txt",
                encryptedFile = "EncryptedData.txt",
                decryptedFile = "DecryptedData.txt";
            // Encrypt a file, encrypted file gets created with encrypted data
            encrypter.EncryptFile(inputFile, encryptedFile);
            // Decrypt a file, decrypted file gets created with decrypted data
            encrypter.DecryptFile(encryptedFile, decryptedFile);
        }
    }
}