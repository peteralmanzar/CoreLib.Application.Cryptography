using System;
using System.Security.Cryptography;
using System.Text;

namespace CoreLib.Application.Cryptography.Extensions
{
    public static class ByteArrayExtensions
    {
        public static string ToStringBit(this byte[] bytes)
        {
            if(bytes is null)
                throw new ArgumentNullException(nameof(bytes));

            return BitConverter
                .ToString(bytes)
                .Replace("-", string.Empty);
        }

        public static string ToStringUTF8(this byte[] bytes)
        {
            if(bytes is null)
                throw new ArgumentNullException(nameof(bytes));

            return UTF8Encoding.UTF8.GetString(bytes);
        }
    }
}
