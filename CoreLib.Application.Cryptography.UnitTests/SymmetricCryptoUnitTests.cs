using CoreLib.Application.Cryptography.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace CoreLib.Application.Cryptography.UnitTests
{
    [TestClass]
    public class SymmetricCryptoUnitTests
    {
        #region Fields
        public readonly string _clearData = "Clear Test Data @#!1.";
        public readonly string _password = "Password@#!1";
        public byte[] _salt;
        public byte[] _key;
        #endregion

        #region Constructors
        public SymmetricCryptoUnitTests()
        {
            _salt = HashingService.GenerateSalt(16);
            _key = HashingService.GenerateKey(_password, _salt);
        }
        #endregion


        #region Public Function
        [TestMethod]
        public void Encrypt_DecryptionEqualsEncrytionData()
        {
            byte[] encryptedData;
            byte[] decryptedData;
            
            using(var cryptoService = new SymmetricCryptoService<AesCryptoServiceProvider>(_key, _salt))
                encryptedData = cryptoService.Encrypt(_clearData.ToBytes());

            using(var cryptoService = new SymmetricCryptoService<AesCryptoServiceProvider>(_key, _salt))
                decryptedData = cryptoService.Decrypt(encryptedData);

            Assert.AreEqual(_clearData, decryptedData.ToStringUTF8());
        }
        #endregion
    }
}
