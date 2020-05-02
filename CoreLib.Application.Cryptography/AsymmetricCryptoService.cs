using System;
using System.Security.Cryptography;

namespace CoreLib.Application.Cryptography
{
    /// <summary>
    /// Provides simplified methods to perform asymmetric encryption using <see cref="RSACryptoServiceProvider"/>.
    /// </summary>
    public static class AsymmetricCryptoService
    {        
        #region Public Methods
        /// <summary>
        /// Encrypts provided data.
        /// </summary>
        /// <param name="inputBytes">Data to be encrypted.</param>
        /// <param name="xmlKeyString">Asymmetric key in xml <see cref="string"/> format.</param>
        /// <returns>The encrypted data.</returns>
        /// <seealso cref="AsymmetricCryptoService.GenerateXMLKeys(KeyNumber)"/>
        /// <seealso cref="AsymmetricCryptoService.GetXMLKeys(string, bool)"/>
        public static byte[] Encrypt(byte[] inputBytes, string xmlKeyString)
        {
            if(inputBytes is null)
                throw new ArgumentNullException(nameof(inputBytes));
            if(string.IsNullOrEmpty(xmlKeyString))
                throw new ArgumentNullException(nameof(xmlKeyString));

            using(var encryptor = new RSACryptoServiceProvider())
            {
                encryptor.FromXmlString(xmlKeyString);
                return encryptor.Encrypt(inputBytes, true);
            }
        }

        /// <summary>
        /// Decrypts provided data.
        /// </summary>
        /// <param name="inputBytes">Data to be encrypted.</param>
        /// <param name="xmlKeyString">Asymmetric key in xml <see cref="string"/> format.</param>
        /// <returns>The decrypted data.</returns>
        /// <seealso cref="AsymmetricCryptoService.GetXMLKeys(string, bool)"/>
        public static byte[] Decrypt(byte[] inputBytes, string xmlKeyString)
        {
            if(inputBytes is null)
                throw new ArgumentNullException(nameof(inputBytes));
            if(string.IsNullOrEmpty(xmlKeyString))
                throw new ArgumentNullException(nameof(xmlKeyString));

            using(var decryptor = new RSACryptoServiceProvider())
            {
                decryptor.FromXmlString(xmlKeyString);
                return decryptor.Decrypt(inputBytes, true);
            }
        }

        /// <summary>
        /// Signs provided hash value.
        /// </summary>
        /// <typeparam name="T"><see cref="HashAlgorithm"/> used to compute signature.</typeparam>
        /// <param name="inputBytes">Data to be encrypted.</param>
        /// <param name="xmlKeyString">Asymmetric key in xml <see cref="string"/> format.</param>
        /// <returns>The signed hash value.</returns>
        /// <remarks>
        ///     Signing of data should be done to the hash value of data. The public key is used
        ///     to generate the signature.
        /// </remarks>
        /// <seealso cref="AsymmetricCryptoService.GetXMLKeys(string, bool)"/>
        public static byte[] SignData<T>(byte[] inputBytes, string xmlKeyString) where T : HashAlgorithm, new()
        {
            if(inputBytes is null)
                throw new ArgumentNullException(nameof(inputBytes));

            using(var cryptoService = new RSACryptoServiceProvider())
            {
                cryptoService.FromXmlString(xmlKeyString);
                return cryptoService.SignData(inputBytes, new T());
            }
        }

        /// <summary>
        ///     Verifies that a digital signature is valid by determining the hash value in the
        ///     signature using the provided public key and comparing it to the hash value of
        ///     the provided data.
        /// </summary>
        /// <typeparam name="T"><see cref="HashAlgorithm"/> used to compute signature.</typeparam>
        /// <param name="inputBytes">The data that was signed.</param>
        /// <param name="xmlKeyString">Asymmetric key in xml <see cref="string"/> format.</param>
        /// <param name="signature">The signature data to be verified.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        /// <remarks>The private key is used to verify signature.</remarks>
        public static bool VerifyData<T>(byte[] inputBytes, string xmlKeyString, byte[] signature) where T : HashAlgorithm, new()
        {
            if(inputBytes is null)
                throw new ArgumentNullException(nameof(inputBytes));
            if(xmlKeyString is null)
                throw new ArgumentNullException(nameof(xmlKeyString));
            if(signature is null)
                throw new ArgumentNullException(nameof(signature));

            using(var cryptoService = new RSACryptoServiceProvider())
            {
                cryptoService.FromXmlString(xmlKeyString);
                return cryptoService.VerifyData(inputBytes, new T(), signature);
            }
        }

        /// <summary>
        /// Generates an asemmetric encryption key.
        /// </summary>
        /// <param name="keyNumber">Specifies whether to generate an asemmetric exchange or 
        /// signature key.</param>
        /// <returns>A generated key.</returns>
        public static string GenerateXMLKeys(KeyNumber keyNumber = KeyNumber.Exchange)
        {
            var cspParameter = new CspParameters();
            cspParameter.Flags |= CspProviderFlags.CreateEphemeralKey;
            cspParameter.KeyNumber = (int)keyNumber;

            using(var cryptoService = new RSACryptoServiceProvider(cspParameter))
                return cryptoService.ToXmlString(true);
        }

        /// <summary>
        /// Stores key in a container.
        /// </summary>
        /// <param name="containerName">Name of the container.</param>
        /// <param name="xmlStringKeys">Asymmetric key in xml <see cref="string"/> format.</param>
        /// <param name="useMachineKeyStore">Specify weather to save container in the machine's keystore 
        /// opposed to the user keystore.</param>
        public static void StoreXMLKeys(string containerName, string xmlStringKeys, bool useMachineKeyStore = false)
        {
            if(string.IsNullOrEmpty(containerName))
                throw new ArgumentNullException(nameof(containerName));
            if(string.IsNullOrEmpty(xmlStringKeys))
                throw new ArgumentNullException(nameof(xmlStringKeys));

            var cspParameter = new CspParameters();
            cspParameter.KeyContainerName = containerName;

            if(useMachineKeyStore)
                cspParameter.Flags |= CspProviderFlags.UseMachineKeyStore;

            using(var cryptoService = new RSACryptoServiceProvider(cspParameter))
                cryptoService.FromXmlString(xmlStringKeys);
        }

        /// <summary>
        /// Retrieve key from container.
        /// </summary>
        /// <param name="containerName">Name of container.</param>
        /// <param name="includePrivateKey"><c>true</c> to include both public and private key; 
        /// <c>false</c> for a public key only</param>
        /// <returns>XML string containing asymmetric key.</returns>
        public static string GetXMLKeys(string containerName, bool includePrivateKey = false)
        {
            if(string.IsNullOrEmpty(containerName))
                throw new ArgumentNullException(nameof(containerName));

            var cspParameter = new CspParameters();
            cspParameter.KeyContainerName = containerName;           

            using(var cryptoService = new RSACryptoServiceProvider(cspParameter))
                return cryptoService.ToXmlString(includePrivateKey);
        }

        /// <summary>
        /// Deletes key container.
        /// </summary>
        /// <param name="containerName">Name of container.</param>
        public static void DeleteKey(string containerName)
        {
            if(string.IsNullOrEmpty(containerName))
                throw new ArgumentNullException(nameof(containerName));

            var cspParameter = new CspParameters();
            cspParameter.KeyContainerName = containerName;

            using(var cryptoService = new RSACryptoServiceProvider(cspParameter))
            {
                cryptoService.PersistKeyInCsp = false;
                cryptoService.Clear();
            }
        }
        #endregion
    }
}
