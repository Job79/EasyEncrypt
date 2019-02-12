/* EasyEncrypt
 * Copyright (C) 2019  henkje (henkje@pm.me)
 * 
 * MIT license
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
        /// Algorithm used for encryption/decryption.
        /// </summary>
        private SymmetricAlgorithm _Algorithm;

        /// <summary>
        /// Create class with an already set up algorithm.
        /// </summary>
        /// <param name="Algorithm">Algorithm wich is alreay set up properly</param>
        public FileEncryption(SymmetricAlgorithm Algorithm)
            => _Algorithm = Algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
        /// <summary>
        /// Create class with an algorithm and overide the key for the selected algorithm.
        /// </summary>
        /// <param name="Algorithm">new algorithm</param>
        /// <param name="Key">Generated key</param>
        public FileEncryption(SymmetricAlgorithm Algorithm, byte[] Key)
        {
            _Algorithm = Algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
            if (Key == null) throw new ArgumentException("Invalid key, key is null.");
            if (!_Algorithm.ValidKeySize(Key.Length * 8)) throw new ArgumentException("Invalid key, key has an invalid size.");
            _Algorithm.Key = Key;
        }
        /// <summary>
        /// Create class and create a new key for the passed algorithm.
        /// </summary>
        /// <param name="Algorithm">New algorithm</param>
        /// <param name="Password">Password, used to generate key</param>
        /// <param name="Salt">Salt, used to make generated key more random(min 8 characters)</param>
        /// <param name="Iterations">Rounds PBKDF2 will make to genarete a key</param>
        public FileEncryption(SymmetricAlgorithm Algorithm, string Password, string Salt, int Iterations = 10000)
        {
            _Algorithm = Algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
            _Algorithm.Key = Encryption.CreateKey(_Algorithm, Password, Salt, Iterations);
        }
        /// <summary>
        /// Create class and create a new key for the passed algorithm with a fixed keysize.
        /// </summary>
        /// <param name="Algorithm">new algorithm</param>
        /// <param name="KeySize">Keysize in bits(8 bits = 1 byte)</param>
        /// <param name="Password">Password, used to generate key</param>
        /// <param name="Salt">Salt, used to make generated key more random(min 8 characters)</param>
        /// <param name="Iterations">Rounds PBKDF2 will make to genarete a key</param>
        public FileEncryption(SymmetricAlgorithm Algorithm, int KeySize, string Password, string Salt, int Iterations = 10000)
        {
            _Algorithm = Algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
            if (!_Algorithm.ValidKeySize(KeySize)) throw new ArgumentException("Invalid key, key has an invalid size.");
            Algorithm.Key = Encryption.CreateKey(KeySize, Password, Salt, Iterations);
        }

        /// <summary>
        /// Encrypt a file.
        /// </summary>
        /// <param name="InputFile">Path to the plain file</param>
        /// <param name="OutputFile">Location to save encrypted file</param>
        /// <param name="BufferSize">BufferSize for reading the inputfile(Default = 1MB)</param>
        public void Encrypt(string InputFile, string OutputFile, int BufferSize = 1048576)
        {
            if (!File.Exists(InputFile)) throw new ArgumentException("Could not encrypt file: File not found.");
            else if (File.Exists(OutputFile)) throw new ArgumentException("Could not encrypt file: File already exists.");

            using (FileStream OutputStream = new FileStream(OutputFile, FileMode.Create))
            {
                _Algorithm.GenerateIV();//Genarate new random IV.
                OutputStream.Write(_Algorithm.IV, 0, _Algorithm.IV.Length);//Write IV to the first bytes(16) of the file.

                using (CryptoStream cs = new CryptoStream(OutputStream, _Algorithm.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    using (FileStream InputStream = new FileStream(InputFile, FileMode.Open))
                    {
                        byte[] Buffer = new byte[BufferSize];
                        int read;

                        while ((read = InputStream.Read(Buffer, 0, Buffer.Length)) > 0)
                            cs.Write(Buffer, 0, read);
                    }
                }
            }
        }

        /// <summary>
        /// Decrypt a file.
        /// </summary>
        /// <param name="InputFile">Path to the encrypted file</param>
        /// <param name="OutputFile">Location to save decrypted file</param>
        /// <param name="BufferSize">BufferSize for reading the inputfile(Default = 1MB)</param>
        public void Decrypt(string InputFile, string OutputFile, int BufferSize = 1048576)
        {
            if (!File.Exists(InputFile)) throw new ArgumentException("Could not decrypt file: File not found.");
            else if (File.Exists(OutputFile)) throw new ArgumentException("Could not decrypt file: File already exists.");

            using (FileStream InputStream = new FileStream(InputFile, FileMode.Open))
            {
                byte[] IV = new byte[_Algorithm.IV.Length];
                InputStream.Read(IV, 0, IV.Length);//Read the IV from the first bytes(16) of the file.
                _Algorithm.IV = IV;

                using (CryptoStream cs = new CryptoStream(InputStream, _Algorithm.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (FileStream OutputStream = new FileStream(OutputFile, FileMode.Create))
                    {
                        int Read;
                        byte[] Buffer = new byte[BufferSize];

                        while ((Read = cs.Read(Buffer, 0, Buffer.Length)) > 0)
                            OutputStream.Write(Buffer, 0, Read);
                    }
                }
            }
        }
    }
}
