using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace EasyEncrypt.Test
{
    [TestClass]
    public class EasyEncryptTest
    {
        [TestMethod]
        public void TestEncryption()
        {
            const string INPUT = "test";
            const string PASSWORD = "Password";
            const string SALT = "SALT1234567";

            SymmetricAlgorithm Algorithm = TripleDES.Create();
            Algorithm.Key = Encryption.CreateKey(Algorithm, PASSWORD, SALT);
            string Encrypted = new Encryption(Algorithm).Encrypt(INPUT);
            string Decrypted = new Encryption(Algorithm).Decrypt(Encrypted);

            Assert.AreEqual(INPUT, Decrypted);

            Encrypted = new Encryption(Algorithm, PASSWORD, SALT).Encrypt(INPUT);
            Decrypted = new Encryption(Algorithm, PASSWORD, SALT).Decrypt(Encrypted);

            Assert.AreEqual(INPUT, Decrypted);

            Encrypted = new Encryption(Algorithm, PASSWORD, SALT).Encrypt(INPUT, Encoding.Unicode);
            Decrypted = new Encryption(Algorithm, PASSWORD, SALT).Decrypt(Encrypted, Encoding.Unicode);

            Assert.AreEqual(INPUT, Decrypted);
        }

        [TestMethod]
        public void TestFileEncryption()
        {
            const string INPUTFILE1 = @"";
            const string OUTPUTFILE1 = @"";

            const string INPUTFILE2 = OUTPUTFILE1;
            const string OUTPUTFILE2 = @"";

            const string PASSWORD = "Password";
            const string SALT = "SALT1234567";

            SymmetricAlgorithm Algorithm = Aes.Create();

            new FileEncryption(Algorithm,PASSWORD,SALT).Encrypt(INPUTFILE1,OUTPUTFILE1);
            new FileEncryption(Algorithm, PASSWORD, SALT).Decrypt(INPUTFILE2,OUTPUTFILE2);

            Assert.AreEqual(new FileInfo(INPUTFILE1).Length, new FileInfo(OUTPUTFILE2).Length);

            File.Delete(OUTPUTFILE1);
            File.Delete(INPUTFILE2);
            if(OUTPUTFILE1 != INPUTFILE2) File.Delete(OUTPUTFILE2);
        }
    }
}
