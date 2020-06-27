using System.IO;

namespace EasyEncrypt2
{
    public static class FileEncryption
    {
        private const int DefaultBufferSize = 1024;

        /// <summary>
        /// Encrypt a file 
        /// </summary>
        /// <param name="encrypt"></param>
        /// <param name="fileIn">unencrypted input file</param>
        /// <param name="fileOut">location of new encrypted file</param>
        /// <param name="bufferSize"></param>
        public static void EncryptFile(this EasyEncrypt encrypt, string fileIn, string fileOut,
            int bufferSize = DefaultBufferSize)
        {
            using var fileInStream = new FileStream(fileIn, FileMode.Open);
            using var fileOutStream = new FileStream(fileOut, FileMode.Create);

            encrypt?.EncryptStream(fileInStream, fileOutStream,false, bufferSize);
        }

        /// <summary>
        /// Decrypt a file 
        /// </summary>
        /// <param name="encrypt">encrypted input file</param>
        /// <param name="fileIn">location of new decrypted file</param>
        /// <param name="fileOut"></param>
        /// <param name="bufferSize"></param>
        public static void DecryptFile(this EasyEncrypt encrypt, string fileIn, string fileOut,
            int bufferSize = DefaultBufferSize)
        {
            using var fileInStream = new FileStream(fileIn, FileMode.Open);
            using var fileOutStream = new FileStream(fileOut, FileMode.Create);

            encrypt?.DecryptStream(fileInStream, fileOutStream,false, bufferSize);
        }
    }
}