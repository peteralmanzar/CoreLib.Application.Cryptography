using CoreLib.Application.Cryptography.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace CoreLib.Application.Cryptography.UnitTests
{
    [TestClass]
    public class AsymmetricCryptoUnitTests
    {
        #region Fields
        public readonly string _clearData = "Password@#!1";
        public readonly string _cspContainerName = "TestKey";
        public readonly string _assemetricXMLString = 
            $"<RSAKeyValue><Modulus>nFpz6c7UKO809u0hrW+mdqYsQjvk0/P7lZPUo2+3OZpCN8gua+5ef95gE8ecrJE3ulv++ufy1ZKbkOmXwY2Ra8ljrVS9xonQqfSYiutKTNsYwpFNV7VYHNCJahUIt3y4xZ2I/hzJ4nVXBH7pJ5jrb/E3WXnyOBrNt3Jc3DRAhsk=</Modulus><Exponent>AQAB</Exponent><P>wnMDFXJe3Ev5nAj+J9QzaczdRYn0AkfLYESGThmR3OL3PXMsX1TfAnRuU48iZmZKCxlTaIFmtqOpmT48fVMDMw==</P><Q>									zdhgox9IGU40Ul0sZy9TSkX+Y4owWQEANZVAQ8M2WUPngvNvkUKUFw9pCnDkI8Mq61HdlyxnMddPe0OlZ2uOEw==</Q><DP>gT5AxniGZJZ7CiNQCtkYczIfwKC49usRWqMxQaftM4wIGWf8DkEzGUaaLh/tFXLXtBjZP5UC2FJf3+NmAUaz0Q==</DP><DQ>Q7VZzC488/3yXelB8srxVawCSlGpJ42ZuQZX9jIfDWu1mjBi0WAaAB/UiFer40uOMYtjHRfA9fcBsOUGYidRuw==</DQ><InverseQ>RZq2GRqpisKwXq351HrwnyvOb/vja86uX/O5WbzKxW5igiwYwTYmQ9n2I6k7e2sGrUP0kj9w9FWnlA3vC7FB/w==</InverseQ><D>h2WpNVL/1Qb5FdBaNqgWPm8+qojVa1rAhlKDdJj80WwtZcL7uEmvGgpHpzlYCvSijsa18y/D0YFpKD+xRFLFF3ij+LK+XwZpfFOdcmbWfygx6zk0t6yI0S4CBZZFCKtTE9pxuRRPBLI/GLiESjVOdHqVK4ReFJzJnMMIK3WItEU=</D></RSAKeyValue>";
        #endregion

        #region Public Function
        [TestMethod]
        public void Encrypt_DecryptionEqualsEncrytionData()
        {
            byte[] encryptedData;
            byte[] decryptedData;            
            
            encryptedData = AsymmetricCryptoService.Encrypt(_clearData.ToBytes(), _assemetricXMLString);            
            decryptedData = AsymmetricCryptoService.Decrypt(encryptedData, _assemetricXMLString);

            Assert.AreEqual(_clearData, decryptedData.ToStringUTF8());
        }

        public void Sign_VerifySignature()
        {
            byte[] signature = AsymmetricCryptoService.SignData<SHA256CryptoServiceProvider>(_clearData.ToBytes(), _assemetricXMLString);
            var signatureVerification = AsymmetricCryptoService.VerifyData<SHA256CryptoServiceProvider>(_clearData.ToBytes(), _assemetricXMLString, signature);

            Assert.IsTrue(signatureVerification);
        }
        #endregion
    }
}
