using System;
using System.Text;

namespace CoreLib.Application.Cryptography.Extensions
{
    public static class StringExtensions
    {
        public static byte[] ToBytes(this string @string)
        {
            if(string.IsNullOrEmpty(@string))
                throw new ArgumentNullException(nameof(@string));
            return Encoding.UTF8.GetBytes(@string);
        }
    }
}
