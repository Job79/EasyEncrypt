/* EasyEncrypt
 * 
 * Copyright (c) 2019 henkje
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

using System;
using System.IO;
using System.Security.Cryptography;

namespace EasyEncrypt
{
    public class FileEncryption
    {
        /// <summary>
        /// Algorithm for encryption and decryption data.
        /// </summary>
        private readonly SymmetricAlgorithm algorithm;

        /// <summary>
        /// Create class with an already set up algorithm.
        /// </summary>
        /// <param name="algorithm">Algorithm wich is alreay set up properly</param>
        public FileEncryption(SymmetricAlgorithm algorithm)
            => this.algorithm = algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
        /// <summary>
        /// Create class with an algorithm and overide the key for the selected algorithm.
        /// </summary>
        /// <param name="algorithm">new algorithm</param>
        /// <param name="key">Generated key</param>
        public FileEncryption(SymmetricAlgorithm algorithm, byte[] key)
        {
            this.algorithm = algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
            if (key == null) throw new ArgumentException("Invalid key, key is null.");
            if (!this.algorithm.ValidKeySize(key.Length * 8)) throw new ArgumentException("Invalid key, key has an invalid size.");
            this.algorithm.Key = key;
        }
        /// <summary>
        /// Create class and create a new key for the passed algorithm.
        /// </summary>
        /// <param name="algorithm">New algorithm</param>
        /// <param name="password">Password, used to generate key</param>
        /// <param name="salt">Salt, used to make generated key more random(min 8 characters)</param>
        /// <param name="iterations">Rounds PBKDF2 will make to genarete a key</param>
        public FileEncryption(SymmetricAlgorithm algorithm, string password, string salt, int iterations = 10000)
        {
            this.algorithm = algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
            this.algorithm.Key = Encryption.CreateKey(this.algorithm, password, salt, iterations);
        }
        /// <summary>
        /// Create class and create a new key for the passed algorithm with a fixed keysize.
        /// </summary>
        /// <param name="algorithm">new algorithm</param>
        /// <param name="keySize">Keysize in bits(8 bits = 1 byte)</param>
        /// <param name="password">Password, used to generate key</param>
        /// <param name="salt">Salt, used to make generated key more random(min 8 characters)</param>
        /// <param name="iterations">Rounds PBKDF2 will make to genarete a key</param>
        public FileEncryption(SymmetricAlgorithm algorithm, int keySize, string password, string salt, int iterations = 10000)
        {
            this.algorithm = algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
            if (!this.algorithm.ValidKeySize(keySize)) throw new ArgumentException("Invalid key, key has an invalid size.");
            this.algorithm.Key = Encryption.CreateKey(keySize, password, salt, iterations);
        }

        /// <summary>
        /// Encrypt a file.
        /// </summary>
        /// <param name="inputFile">Path of the plain file</param>
        /// <param name="outputFile">Location to save encrypted file</param>
        /// <param name="bufferSize">BufferSize for reading the inputfile(Default = 1MB)</param>
        public void Encrypt(string inputFile, string outputFile, int bufferSize = 1048576)
        {
            if (!File.Exists(inputFile)) throw new ArgumentException("Could not encrypt file: File not found.");
            else if (File.Exists(outputFile)) throw new ArgumentException("Could not encrypt file: File already exists.");

            using (FileStream outputStream = new FileStream(outputFile, FileMode.Create))
            {
                algorithm.GenerateIV();//Genarate new random IV.
                outputStream.Write(algorithm.IV, 0, algorithm.IV.Length);//Write IV to the first bytes(16) of the file.

                using (CryptoStream cs = new CryptoStream(outputStream, algorithm.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    using (FileStream inputStream = new FileStream(inputFile, FileMode.Open))
                    {
                        byte[] buffer = new byte[bufferSize];
                        int read;

                        while ((read = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                            cs.Write(buffer, 0, read);
                    }
                }
            }
        }

        /// <summary>
        /// Decrypt a file.
        /// </summary>
        /// <param name="inputFile">Path of the encrypted file</param>
        /// <param name="outputFile">Location to save decrypted file</param>
        /// <param name="bufferSize">BufferSize for reading the inputfile(Default = 1MB)</param>
        public void Decrypt(string inputFile, string outputFile, int bufferSize = 1048576)
        {
            if (!File.Exists(inputFile)) throw new ArgumentException("Could not decrypt file: File not found.");
            else if (File.Exists(outputFile)) throw new ArgumentException("Could not decrypt file: File already exists.");

            using (FileStream inputStream = new FileStream(inputFile, FileMode.Open))
            {
                byte[] IV = new byte[algorithm.IV.Length];
                inputStream.Read(IV, 0, IV.Length);//Read the IV from the first bytes(16) of the file.
                algorithm.IV = IV;

                using (CryptoStream cs = new CryptoStream(inputStream, algorithm.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (FileStream outputStream = new FileStream(outputFile, FileMode.Create))
                    {
                        byte[] buffer = new byte[bufferSize];
                        int read;

                        while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                            outputStream.Write(buffer, 0, read);
                    }
                }
            }
        }

        /// <summary>
        /// Return the current key.
        /// </summary>
        /// <returns>Encryption key</returns>
        public byte[] GetKey()
            => algorithm.Key;
    }
}
