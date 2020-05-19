using NUnit.Framework;

namespace EasyEncrypt2.Test
{
    public class EncryptionTest
    {
        [Test]
        public void TestEncryptDecrypt()
        {
            using var encrypter = new EasyEncrypt();

            string data = "fasfeaw12fewavgffewa4rvar31242`343e12123`";
            string encrypted = encrypter.Encrypt(data);
            string decrypted = encrypter.Decrypt(encrypted);
            
            Assert.AreEqual(data,decrypted);
            Assert.AreNotEqual(data,encrypted);
        }
    }
}