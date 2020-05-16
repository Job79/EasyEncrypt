using System.IO;

namespace EasyEncrypt
{
    public static class FileEncryption
    {
        private const int DefaultBufferSize = 1024;

        public static void EncryptFile(this EasyEncrypt encrypt, string fileIn, string fileOut,
            int bufferSize = DefaultBufferSize)
        {
            using var fileInStream = new FileStream(fileIn, FileMode.Open);
            using var fileOutStream = new FileStream(fileOut, FileMode.Create);

            encrypt?.EncryptStream(fileInStream, fileOutStream, bufferSize);
        }

        public static void DecryptFile(this EasyEncrypt encrypt, string fileIn, string fileOut,
            int bufferSize = DefaultBufferSize)
        {
            using var fileInStream = new FileStream(fileIn, FileMode.Open);
            using var fileOutStream = new FileStream(fileOut, FileMode.Create);

            encrypt?.DecryptStream(fileInStream, fileOutStream, bufferSize);
        }
    }
}