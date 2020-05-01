using CoreLib.Application.Cryptography.Extensions;
using System;
using System.Security.Cryptography;

namespace CoreLib.Application.Cryptography
{
    /// <summary>
    /// Provides methods generate different hashes.
    /// </summary>
    public static class HashingService
    {
        #region Public Methods
        /// <summary>
        /// Provides computed hash value.
        /// </summary>
        /// <typeparam name="T"><see cref="HashAlgorithm"/> used to compute hash value.</typeparam>
        /// <param name="inputBytes">Data used to compute hash value.</param>
        /// <returns>Computed hash value of specified data.</returns>
        /// <seealso cref="MD5CryptoServiceProvider"/>
        /// <seealso cref="SHA1CryptoServiceProvider"/>
        /// <seealso cref="SHA256CryptoServiceProvider"/>
        /// <seealso cref="SHA384CryptoServiceProvider"/>
        /// <seealso cref="SHA512CryptoServiceProvider"/>
        public static byte[] ComputeHash<T>(byte[] inputBytes) where T : HashAlgorithm, new()
        {
            if(inputBytes is null)
                throw new ArgumentNullException(nameof(inputBytes));

            using(var hashingAlgorithm = new T())
                return hashingAlgorithm.ComputeHash(inputBytes);
        }

        /// <summary>
        /// Provides a cryptographically strong array of random bytes.
        /// </summary>
        /// <param name="saltSize">Size of hash.</param>
        /// <returns>A byte array that represents a hash value.</returns>
        /// <remarks>If <paramref name="saltSize"/> is less than 1 it default to 1.</remarks>
        public static byte[] GenerateSalt(int saltSize = 8)
        {
            if(saltSize < 1)
                saltSize = 1;

            var result = new byte[saltSize];

            using(var rngCryptoService = new RNGCryptoServiceProvider())
                rngCryptoService.GetBytes(result);

            return result;
        }

        /// <summary>
        /// Provides psudo-random key.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="salt">The salt used to derive the key.</param>
        /// <param name="keySize">The size of the key.</param>
        /// <param name="iterations">The number of iterations to run deriviation operation</param>
        /// <returns>The derived key.</returns>
        /// <remarks>
        /// If <paramref name="keySize"/> or <paramref name="iterations"/> is less than 1 they
        /// default back to one. If the salt is null it defaults to an
        /// </remarks>
        public static byte[] GenerateKey(string password, byte[] salt = null, int keySize = 16, int iterations = 1000)
        {
            if(string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));
            if(!(salt?.Length > 0))
                salt = new byte[8];
            if(keySize < 1)
                keySize = 1;
            if(iterations < 1)
                iterations = 1;

            using(var rfc2898Service = new Rfc2898DeriveBytes(password, salt, iterations))
                return rfc2898Service.GetBytes(keySize);
        }

        /// <summary>
        /// Provides psudo-random key.
        /// </summary>
        /// <param name="keySize">The size of the key.</param>
        /// <returns>The derived key.</returns>
        public static byte[] GenerateKey(int keySize = 16)
        {
            byte[] password = HashingService.GenerateSalt(),
                   salt = HashingService.GenerateSalt();
            var iterations = 1000;

            return GenerateKey(password.ToStringUTF8(), salt, keySize, iterations);
        }

        /// <summary>
        /// Compares two hash values.
        /// </summary>
        /// <param name="hash">Hash value to compare.</param>
        /// <param name="comparingHash">Hash value comparing to.</param>
        /// <returns><c>true</c> if the hashes provided hashes are the same; otherwise, <c>false</c>.</returns>
        public static bool CompareHashes(byte[] hash, byte[] comparingHash)
        {
            if(hash is null)
                throw new ArgumentNullException(nameof(hash));
            if(comparingHash is null)
                throw new ArgumentNullException(nameof(comparingHash));

            if(hash.Length != comparingHash.Length)
                return false;

            var result = true;

            for(int i = 0; i < hash.Length - 1; i++)
                if(hash[i] != comparingHash[i])
                    result = false;

            return result;
        }
        #endregion
    }
}
