using System;
using System.Security.Cryptography;

namespace CoreLib.Application.Cryptography
{
    /// <summary>
    /// Provides methods to protect data using  current user or machine profiles.
    /// </summary>
    public static class LocalUserDataProtector
    {
        #region Public Methods
        /// <summary>
        /// Encrypts data using user or current machine's credentials
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <param name="entropy">An additional hash to increase security 
        /// complexity to the encryption.</param>
        /// <param name="protectionScope">Enumaration that defines the scope of the 
        /// local data encryptions.</param>
        /// <returns>The encrypted data.</returns>
        /// <exception cref="NotSupportedException">Thrown if method is ran on a non Windows machine.</exception>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is null.</exception>
        /// <remarks>
        /// Only the current windows user or machine will be able to decrpyt data.
        /// </remarks>
        public static byte[] ProtectData(byte[] data, byte[] entropy = null, DataProtectionScope protectionScope = DataProtectionScope.CurrentUser)
        {
            return ProtectedData.Protect(data, entropy, protectionScope);
        }

        /// <summary>
        /// Decrypts data using the user or current machine's credentials
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <param name="entropy">An additional hash to increase security 
        /// complexity to the encryption.</param>
        /// <param name="protectionScope">Enumaration that defines the scope of the 
        /// local data encryptions.</param>
        /// <returns>The decrypted data.</returns>
        /// <exception cref="NotSupportedException">Thrown if method is ran on a non Windows Machine.</exception>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="data"/> is null.</exception>
        public static byte[] UnProtect(byte[] data, byte[] entropy = null, DataProtectionScope protectionScope = DataProtectionScope.CurrentUser)
        {
            return ProtectedData.Unprotect(data, entropy, protectionScope);
        }
        #endregion
    }
}
