using System.IO;
using NUnit.Framework;

namespace EasyEncrypt2.Test
{
    public class FileEncryptionTest
    {
        [Test]
        public void TestEncryptDecrypt()
        {
           using var encrypter = new EasyEncrypt(); 
           encrypter.EncryptFile("Data.txt","Encrypted.txt");
           encrypter.DecryptFile("Encrypted.txt","Decrypted.txt");

           string data = File.ReadAllText("Data.txt"),
               encrypted = File.ReadAllText("Encrypted.txt"),
               decrypted = File.ReadAllText("Decrypted.txt");
           Assert.AreEqual(data,decrypted);
           Assert.AreNotEqual(data,encrypted);
        }
    }
}