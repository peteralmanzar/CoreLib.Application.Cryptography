using System;
using System.Security.Cryptography;

namespace CoreLib.Application.Cryptography
{
    /// <summary>
    /// Provides methods to perform symmetric encryption.
    /// </summary>
    /// <typeparam name="T"><see cref="SymmetricAlgorithm"/> used to perform encryption.</typeparam>
    public class SymmetricCryptoService<T> : IDisposable
        where T : SymmetricAlgorithm, new()
    {
        #region Properties
        /// <summary>
        /// Gets or sets the secret key for the symmetric algorithm.
        /// </summary>
        public byte[] Key
        {
            get => _algorithm.Key;
            protected set => _algorithm.Key = value;
        }
        /// <summary>
        /// Gets or sets the initialization vector.
        /// </summary>
        public byte[] IV
        {
            get => _algorithm.IV;
            protected set => _algorithm.IV = value;
        }
        #endregion

        #region Fields
        protected readonly T _algorithm = new T();
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricCryptoService{T}"/>.
        /// </summary>
        /// <param name="key">The generated secret key to use for the symmetric algorithm.</param>
        /// <param name="iV">The generated initialization vector to use for 
        /// the symmetric algorithm.</param>
        /// <seealso cref="HashingService.GenerateKey(int)"/>
        /// <seealso cref="HashingService.GenerateSalt(int)"/>
        public SymmetricCryptoService(byte[] key = null, byte[] iV = null)
        {
            if(key is null)
                throw new ArgumentNullException(nameof(key));
            if(iV is null)
                throw new ArgumentNullException(nameof(iV));

            Key = key;
            IV = iV;

            setAlgorithmMode();
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricCryptoService{T}"/>
        /// </summary>
        /// <param name="keySize">Size of the generated secret key to use for the symmetric algorithm.</param>
        /// <param name="iVSize">Size of the generated initialization vector to use for 
        /// the symmetric algorithm.</param>
        public SymmetricCryptoService(int keySize = 16, int iVSize = 8)
        {
            if(keySize < 1)
                throw new ArgumentOutOfRangeException(nameof(keySize), 
                    $"{nameof(keySize)} cannot be less than 1.");
            if(iVSize < 1)
                throw new ArgumentOutOfRangeException(nameof(iVSize), 
                    $"{nameof(iVSize)} cannot be less than 1.");
            
            Key = HashingService.GenerateKey(keySize);
            IV = HashingService.GenerateSalt();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Encrypts provided data.
        /// </summary>
        /// <param name="inputBytes">Data to be encrypted.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] inputBytes)
        {
            if(inputBytes is null)
                throw new ArgumentNullException(nameof(inputBytes));

            using(var encryptor = _algorithm.CreateEncryptor(Key, IV))
                return encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
        }

        /// <summary>
        /// Decrypts provided data.
        /// </summary>
        /// <param name="inputBytes">data to be decrypted.</param>
        /// <returns>The decrypted data.</returns>
        public byte[] Decrypt(byte[] inputBytes)
        {
            if(inputBytes is null)
                throw new ArgumentNullException(nameof(inputBytes));

            using(var decryptor = _algorithm.CreateDecryptor(Key, IV))
                return decryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
        }

        public virtual void Dispose()
        {
            _algorithm.Dispose();
        }
        #endregion

        #region Private Methods
        private void setAlgorithmMode()
        {
            if(_algorithm.IV is null || _algorithm.IV == default)
                _algorithm.Mode = CipherMode.ECB;
            else
                _algorithm.Mode = CipherMode.CBC;
        }
        #endregion
    }
}
