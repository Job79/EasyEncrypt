# HenkEncrypt
HenkEncrypt can be used to encrypt strings, byte arrays, files and folders.
HenkEncrypt is easy to use and advanced, it can be used with AES and the other symmetric algorithms.

This example will explain you how you can use HenkEcnrypt:
```cs
using System;
using encryption;
using System.Security.Cryptography;
using System.Text;

namespace ExampleHenkEncrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            string PlainText = Console.ReadLine();
            string Password = Console.ReadLine();

            string Salt = "Salt,used to generate key";
            //create a key for aes(256 bits, 32 bytes)
            byte[] Key = Encryption.CreateKey(Aes.Create(),Password,Salt);
            //create a key for TrippleDes
            byte[] TrippleDESKey = Encryption.CreateKey(TripleDES.Create(), Password,Salt);
            //create a key for des
            byte[] DESKey = Encryption.CreateKey(DES.Create(), Password,Salt);

            //generate a key advanced
            //Aes.Create is the alghoritm, this is used when you dont use a key length.
            //Salt is a random sting, it will be converted to bytes and used as salt.
            //10000 are the iterations that will be used to create the key(using pbkdf2)
            //16 is the keysize in bytes, 16 * 8 = 128 so we will have a 128 bits key
            byte[] AdvancedKey = Encryption.CreateKey(Aes.Create(), Password, Salt, 10000,16);
            //other way
            Encryption.Encrypt(Aes.Create(),"data", Password, Salt, 10000, 16);

            //this will do the same
            //but wile give a different output, because it use a random iv
            //use DES.Create() for DES and other alghoritms
            Console.WriteLine(Encryption.Encrypt(Aes.Create(),PlainText,Key));
            Console.WriteLine(Encryption.Encrypt(Aes.Create(),PlainText,Password,Salt));

            Console.WriteLine(Convert.ToBase64String(Encryption.Encrypt(Aes.Create(), Encoding.UTF8.GetBytes(PlainText), Key)));
            Console.WriteLine(Convert.ToBase64String(Encryption.Encrypt(Aes.Create(), Encoding.UTF8.GetBytes(PlainText), Password,Salt)));

            string Encrypted =  Encryption.Encrypt(Aes.Create(), PlainText, Password,Salt);
            Console.WriteLine(Encryption.Decrypt(Aes.Create(),Encrypted,Password,Salt));

            Encrypted = Encryption.Encrypt(DES.Create(), PlainText, Password,Salt);
            Console.WriteLine(Encryption.Decrypt(DES.Create(), Encrypted, Password,Salt));

            Encrypted = Encryption.Encrypt(TripleDES.Create(), PlainText, Password,Salt);
            Console.WriteLine(Encryption.Decrypt(TripleDES.Create(), Encrypted, Password,Salt));

            //file encryption
            //can be used on evry file size, but on big files it will take some time
            string FileIn = @"C:\test.txt";
            string FileOut = @"C:\encrypted.txt";
            FileEncryption.Encrypt(Aes.Create(), FileIn, FileOut,Password,Salt);
            //FileEncryption.Encrypt(Aes.Create(), FileIn, FileOut, Key);
            //FileEncryption.Encrypt(DES.Create(), FileIn, FileOut, Password,Salt);
            //FileEncryption.Encrypt(TripleDES.Create(), FileIn, FileOut, Password,Salt);

            FileIn = @"C:\encrypted.txt";
            FileOut = @"C:\decrypted.txt";
            FileEncryption.Decrypt(Aes.Create(),FileIn,FileOut,Password,Salt);
            //FileEncryption.Decrypt(Aes.Create(), FileIn, FileOut, Key);
            //FileEncryption.Decrypt(DES.Create(), FileIn, FileOut, Password,Salt);
            //FileEncryption.Decrypt(TripleDES.Create(), FileIn, FileOut, Password,Salt);

            /*file encryption take blocks of a file and encrypt that blocks
             *you can change the size of the blocks with the following:
             * FileEncryption.Encrypt(Aes.Create(), FileIn, FileOut, Key,1048576);
             * FileEncryption.Encrypt(Aes.Create(), FileIn, FileOut, Password, Salt, BufferSize: 1048576);
             * will works the same on the folders
             */

            //folder encryption, can be used with other alghoritms like FileEncryption
            string FolderIn = @"C:\test";
            FileOut = @"C:\encrypted.ENCRYPTED";
            FolderEncryption.Encrypt(Aes.Create(),FolderIn,FileOut,Password,Salt);

            string FolderOut = @"C:\decrypted";
            FolderEncryption.Decrypt(Aes.Create(), FileOut, FolderOut, Password,Salt);
            Console.ReadLine();
        }
    }
}
```
