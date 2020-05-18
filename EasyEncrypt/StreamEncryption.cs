using System;
using System.IO;
using System.Security.Cryptography;

namespace EasyEncrypt
{
    public static class StreamEncryption
    {
        private const int DefaultBufferSize = 1024;
        
        /// <summary>
        /// Encrypt a stream
        /// </summary>
        /// <param name="encrypt"></param>
        /// <param name="inputStream">readable stream with unencrypted data</param>
        /// <param name="outputStream">writable stream for encrypted data</param>
        /// <param name="bufferSize"></param>
        /// <exception cref="ArgumentException"></exception>
        public static void EncryptStream(this EasyEncrypt encrypt, Stream inputStream, Stream outputStream,
            int bufferSize = DefaultBufferSize)
        {
            if (encrypt == null) throw new ArgumentException("Can't encrypt data: encrypt class is null");
            if (inputStream == null || !inputStream.CanRead)
                throw new ArgumentException("Can't encrypt data: inputStream is not readable");
            if (outputStream == null || !outputStream.CanWrite)
                throw new ArgumentException("Can't encrypt data: output stream is not writable");

            encrypt.Algorithm.GenerateIV();
            outputStream.Write(encrypt.Algorithm.IV, 0, encrypt.Algorithm.IV.Length);

           using var cs = new CryptoStream(inputStream,
               encrypt.Algorithm.CreateEncryptor(encrypt.Algorithm.Key, encrypt.Algorithm.IV), CryptoStreamMode.Read);
            
           var buffer = new byte[bufferSize];
           int read;

           while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
               outputStream.Write(buffer, 0, read); 
           
        }

        /// <summary>
        /// Decrypt a stream 
        /// </summary>
        /// <param name="encrypt"></param>
        /// <param name="inputStream">readable stream with encrypted data</param>
        /// <param name="outputStream">writable stream for decrypted data</param>
        /// <param name="bufferSize"></param>
        /// <exception cref="ArgumentException"></exception>
        public static void DecryptStream(this EasyEncrypt encrypt, Stream inputStream, Stream outputStream,
            int bufferSize = DefaultBufferSize)
        {
            if (encrypt == null) throw new ArgumentException("Can't encrypt data: encrypt class is null");
            if (inputStream == null || !inputStream.CanRead)
                throw new ArgumentException("Can't encrypt data: inputStream is not readable");
            if (outputStream == null || !outputStream.CanWrite)
                throw new ArgumentException("Can't encrypt data: output stream is not writable");

            byte[] iv = new byte[encrypt.Algorithm.IV.Length];
            inputStream.Read(iv, 0, iv.Length);
            encrypt.Algorithm.IV = iv;

            using var cs = new CryptoStream(inputStream,
                encrypt.Algorithm.CreateDecryptor(encrypt.Algorithm.Key, encrypt.Algorithm.IV), CryptoStreamMode.Read);

            var buffer = new byte[bufferSize];
            int read;

            while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                outputStream.Write(buffer, 0, read);
        }
    }
}