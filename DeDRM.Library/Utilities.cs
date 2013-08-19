using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DeDRM.Library
{
    public class Utilities
    {
        public static string DecodeBase64(String encodedString, out byte[] data)
        {
            data = Convert.FromBase64String(encodedString);
            string decodedString = Encoding.UTF8.GetString(data);
            return decodedString;
        }
    }
}
