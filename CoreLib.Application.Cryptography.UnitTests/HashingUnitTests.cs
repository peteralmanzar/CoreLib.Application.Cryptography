using CoreLib.Application.Cryptography.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace CoreLib.Application.Cryptography.UnitTests
{
    [TestClass]
    public class HashingUnitTests
    {
        #region Fields
        private readonly string _clearData = "Clear Test Data @#!1.";

        private readonly string _md5Hash = "D8BB4D0B1176A860060F35C04D814F25";
        private readonly string _sha1Hash = "34250D60C4981C626F0CC86DD576D48F1934A2FC";
        private readonly string _sha256Hash = "39C30FBBE6AD037328397A9D2262FB4274E82B0289F318CDC28F979FF2A87B92";
        private readonly string _sha384Hash = "E99A13037DD8B43B6E3E4917932076E0A8E3F09BD74D8E2FE5EED9AFCADB5327232CCE2262D4222F7891FC56872D71DC";
        private readonly string _sha512Hash = "AD6114DDE807EBF83898CDC1FDF87288213DC6FDF9E2CD061B9DA9D22DD26795C7A73DFC84C5F164F1080CBC6408BFCDF0A61119A44478F9DC1A0CC954B912BB";
        #endregion

        #region Public Methods
        [TestMethod]
        public void Hash_CorrectMD5Hash()
        {
            byte[] generatedHash = HashingService.ComputeHash<MD5CryptoServiceProvider>(_clearData.ToBytes());
            Assert.AreEqual(_md5Hash, generatedHash.ToStringBit());
        }

        [TestMethod]
        public void Hash_CorrentSHA1Hash()
        {
            byte[] generatedHash = HashingService.ComputeHash<SHA1CryptoServiceProvider>(_clearData.ToBytes());
            Assert.AreEqual(_sha1Hash, generatedHash.ToStringBit());
        }

        [TestMethod]
        public void Hash_CorrentSHA256Hash()
        {
            byte[] generatedHash = HashingService.ComputeHash<SHA256CryptoServiceProvider>(_clearData.ToBytes());
            Assert.AreEqual(_sha256Hash, generatedHash.ToStringBit());
        }

        [TestMethod]
        public void Hash_CorrentSHA384Hash()
        {
            byte[] generatedHash = HashingService.ComputeHash<SHA384CryptoServiceProvider>(_clearData.ToBytes());
            Assert.AreEqual(_sha384Hash, generatedHash.ToStringBit());
        }

        [TestMethod]
        public void Hash_CorrentSHA512Hash()
        {
            byte[] generatedHash = HashingService.ComputeHash<SHA512CryptoServiceProvider>(_clearData.ToBytes());
            Assert.AreEqual(_sha512Hash, generatedHash.ToStringBit());
        }
        #endregion
    }
}
