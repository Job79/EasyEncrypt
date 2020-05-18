using System.IO;
using System.Linq;
using System.Text;
using NUnit.Framework;

namespace EasyEncrypt.Test
{
    public class StreamEncryptionTest
    {
        [Test]
        public void TestStreams()
        {
            using var encryptor = new EasyEncrypt();

            using var input = new MemoryStream(Encoding.UTF8.GetBytes("test"));
            var encrypted = new MemoryStream();
            var decrypted = new MemoryStream();
            encryptor.EncryptStream(input, encrypted);
            encryptor.DecryptStream(new MemoryStream(encrypted.ToArray()), decrypted);

            Assert.IsTrue(input.ToArray().SequenceEqual(decrypted.ToArray()));
        }
    }
}