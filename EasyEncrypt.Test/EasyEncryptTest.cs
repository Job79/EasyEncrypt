/* EasyEncrypt.Test
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
            const string input = "input";
            const string password = "Password";
            const string salt = "12345678";

            SymmetricAlgorithm algorithm = TripleDES.Create();
            algorithm.Key = Encryption.CreateKey(algorithm, password, salt);
            string encrypted = new Encryption(algorithm).Encrypt(input);
            string decrypted = new Encryption(algorithm).Decrypt(encrypted);

            Assert.AreEqual(input, decrypted);

            encrypted = new Encryption(algorithm, password, salt).Encrypt(input);
            decrypted = new Encryption(algorithm, password, salt).Decrypt(encrypted);

            Assert.AreEqual(input, decrypted);

            encrypted = new Encryption(algorithm, password, salt).Encrypt(input, Encoding.Unicode);
            decrypted = new Encryption(algorithm, password, salt).Decrypt(encrypted, Encoding.Unicode);

            Assert.AreEqual(input, decrypted);
        }

        [TestMethod]
        public void TestFileEncryption()
        {
            const string inputFile1 = @"";
            const string outputFile1 = @"";

            const string inputFile2 = outputFile1;
            const string outputFile2 = @"";

            const string password = "Password";
            const string salt = "SALT1234567";

            SymmetricAlgorithm algorithm = Aes.Create();

            new FileEncryption(algorithm, password,salt).Encrypt(inputFile1,outputFile1);
            new FileEncryption(algorithm, password, salt).Decrypt(inputFile2,outputFile2);

            Assert.AreEqual(new FileInfo(inputFile1).Length, new FileInfo(outputFile2).Length);

            File.Delete(outputFile1);
            File.Delete(outputFile2);
            if(outputFile1 != inputFile2) File.Delete(outputFile2);
        }
    }
}
