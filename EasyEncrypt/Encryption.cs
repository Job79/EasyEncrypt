using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace EasyEncrypt2
{
    /// <summary>
    /// Class that provides basic encryption functionality
    /// </summary>
    public class EasyEncrypt : IDisposable
    {
        /// <summary>
        /// Algorithm that is used for encrypting and decrypting data
        /// </summary> 
        public readonly SymmetricAlgorithm Algorithm;

        /// <summary>
        /// </summary>
        /// <param name="algorithm">algorithm used for encryption, Aes if null</param>
        /// <param name="key">key used for encryption, secure random if null</param>
        /// <exception cref="ArgumentException">can't create EasyEncrypt: key is invalid</exception>
        public EasyEncrypt(SymmetricAlgorithm algorithm = null, byte[] key = null)
        {
            Algorithm = algorithm ?? Aes.Create();
            if (key == null) Algorithm.GenerateKey();
            else if (Algorithm.ValidKeySize(key.Length * 8)) Algorithm.Key = key;
            else throw new ArgumentException("Can't create EasyEncrypt: key is invalid");
        }

        /// <summary>
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt">random string to make key generation more random</param>
        /// <param name="algorithm">algorithm used for encryption, Aes if null</param>
        /// <param name="keysize">size of generated key, greatest key for algorithm if null</param>
        /// <exception cref="ArgumentException">can't create EasyEncrypt: key is invalid</exception>
        public EasyEncrypt(string password, string salt, SymmetricAlgorithm algorithm = null, int? keysize = null)
        {
            Algorithm = algorithm ?? Aes.Create();
            keysize ??= Algorithm.LegalKeySizes[0].MaxSize;
            Algorithm.Key = CreateKey(password, salt, (int) keysize);
        }

        /// <summary>
        /// Encrypt a string 
        /// </summary>
        /// <param name="text"></param>
        /// <param name="encoder">encoding type (Default: UTF8)</param>
        /// <returns>IV + encrypted text</returns>
        public string Encrypt(string text, Encoding encoder = null)
            => Convert.ToBase64String(Encrypt(
                (encoder ?? Encoding.UTF8).GetBytes(
                    text ?? throw new ArgumentException("Can't encrypt text: text is null"))));

        /// <summary>
        /// Encrypt a byte[] 
        /// </summary>
        /// <param name="data"></param>
        /// <returns>IV + encrypted data</returns>
        /// <exception cref="Exception">can't encrypt data: data is null</exception>
        public byte[] Encrypt(byte[] data)
        {
            if (data == null) throw new ArgumentException("Can't encrypt data: data is null");

            using var ms = new MemoryStream();
            Algorithm.GenerateIV();
            ms.Write(Algorithm.IV, 0, Algorithm.IV.Length);

            using var encrypter = Algorithm.CreateEncryptor(Algorithm.Key, Algorithm.IV);
            using var cs = new CryptoStream(ms, encrypter, CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();

            return ms.ToArray();
        }

        /// <summary>
        /// Decrypt a string 
        /// </summary>
        /// <param name="text"></param>
        /// <param name="encoder">encoding type (Default: UTF8)</param>
        /// <returns>IV + decrypted data</returns>
        public string Decrypt(string text, Encoding encoder = null)
            => (encoder ?? Encoding.UTF8).GetString(Decrypt(
                Convert.FromBase64String(
                    text ?? throw new ArgumentException("Can't decrypt data: text is null"))));

        /// <summary>
        /// Decrypt a byte[]
        /// </summary>
        /// <param name="data"></param>
        /// <returns>IV + decrypted data</returns>
        /// <exception cref="ArgumentException">can't decrypt data: data is invalid</exception>
        public byte[] Decrypt(byte[] data)
        {
            if (data == null || data.Length <= 4) throw new ArgumentException("Can't decrypt data: data is invalid");

            byte[] iv = new byte[Algorithm.IV.Length];
            Buffer.BlockCopy(data, 0, iv, 0, iv.Length);
            Algorithm.IV = iv;

            using var ms = new MemoryStream();
            using var decrypter = Algorithm.CreateDecryptor(Algorithm.Key, Algorithm.IV);
            using var cs = new CryptoStream(ms, decrypter, CryptoStreamMode.Write);
            cs.Write(data, iv.Length, data.Length - iv.Length);
            cs.FlushFinalBlock();

            return ms.ToArray();
        }

        /// <summary>
        /// Return the current key
        /// </summary>
        /// <returns>encryption key</returns>
        public byte[] GetKey() => Algorithm.Key;

        /// <summary>
        /// Dispose algorithm 
        /// </summary>
        public void Dispose()
        {
            Algorithm?.Dispose();
        }

        /// <summary>
        /// Generate new key
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="keysize">keysize in bits</param>
        /// <returns>generated key</returns>
        /// <exception cref="ArgumentException">can't create key: {reason}</exception>
        public static byte[] CreateKey(string password, string salt, int keysize)
        {
            if (string.IsNullOrEmpty(password)) throw new ArgumentException("Can't create key: password is empty");
            if (salt == null || salt.Length < 8) throw new ArgumentException("Can't create key: salt is too short");
            if (keysize <= 0) throw new ArgumentException("Can't create key: keysize is invalid");

            using var rfc = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(salt));
            return rfc.GetBytes(keysize / 8);
        }
    }
}