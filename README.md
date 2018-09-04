# HenkEncrypt

example:
```cs
using System;
using encryption;
using System.Security.Cryptography;
using System.Text;

namespace test_encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            string PlainText = Console.ReadLine();
            string Password = Console.ReadLine();

            //create a key for aes(256 bits, 32 bytes)
            byte[] Key = Encryption.CreateKey(Aes.Create(),Password);
            //create a key for TrippleDes
            //byte[] TrippleDESKey = Encryption.CreateKey(TripleDES.Create(), Password);
            //create a key for des
            //byte[] DESKey = Encryption.CreateKey(DES.Create(), Password);

            //this does all the same
            //but wile give a different output, because it use a random iv
            //use DES.Create() for DES and other alghoritms
            Console.WriteLine(Encryption.Encrypt(Aes.Create(),PlainText,Key));
            Console.WriteLine(Encryption.Encrypt(Aes.Create(),PlainText,Password));

            Console.WriteLine(Convert.ToBase64String(Encryption.Encrypt(Aes.Create(), Encoding.UTF8.GetBytes(PlainText), Key)));
            Console.WriteLine(Convert.ToBase64String(Encryption.Encrypt(Aes.Create(), Encoding.UTF8.GetBytes(PlainText), Password)));

            string Encrypted =  Encryption.Encrypt(Aes.Create(), PlainText, Password);
            Console.WriteLine(Encryption.Decrypt(Aes.Create(),Encrypted,Password));

            Encrypted = Encryption.Encrypt(DES.Create(), PlainText, Password);
            Console.WriteLine(Encryption.Decrypt(DES.Create(), Encrypted, Password));

            Encrypted = Encryption.Encrypt(TripleDES.Create(), PlainText, Password);
            Console.WriteLine(Encryption.Decrypt(TripleDES.Create(), Encrypted, Password));

            //file encryption
            //can be used on evry file size, but on big files it will take some time
            string FileIn = @"C:\test.txt";
            string FileOut = @"C:\encrypted.txt";
            FileEncryption.Encrypt(Aes.Create(), FileIn, FileOut,Password);
            //FileEncryption.Encrypt(Aes.Create(), FileIn, FileOut, Key);
            //FileEncryption.Encrypt(DES.Create(), FileIn, FileOut, Password);
            //FileEncryption.Encrypt(TripleDES.Create(), FileIn, FileOut, Password);

            FileIn = @"C:\encrypted.txt";
            FileOut = @"C:\decrypted.txt";
            FileEncryption.Decrypt(Aes.Create(),FileIn,FileOut,Password);
            //FileEncryption.Decrypt(Aes.Create(), FileIn, FileOut, Key);
            //FileEncryption.Decrypt(DES.Create(), FileIn, FileOut, Password);
            //FileEncryption.Decrypt(TripleDES.Create(), FileIn, FileOut, Password);

            //folder encryption, can be used with other alghoritms like fileencryption
            string FolderIn = @"C:\test";
            FileOut = @"C:\encrypted.ENCRYPTED";
            FolderEncryption.Encrypt(Aes.Create(),FolderIn,FileOut,Password);

            string FolderOut = @"C:\decrypted";
            FolderEncryption.Decrypt(Aes.Create(), FileOut, FolderOut, Password);
            Console.ReadLine();
        }
    }
}```
