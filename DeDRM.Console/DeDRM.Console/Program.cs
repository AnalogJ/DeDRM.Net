using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DeDRM.Library.Kobo.Epub;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Math;
using DeDRM.Library;
using DeDRM.Library.Crypto;


namespace DeDRM.Console
{
    class Program
    {
        static void Main(string[] args)
        {
            //MobiBook book = new MobiBook("C:\\test\\adobekey_1.der");
            Byte[] derContent = File.ReadAllBytes("C:\\test\\adobekey_1.der");


            Handler epubParser = new Handler(derContent);
            epubParser.RemoveDrm("C:\\test\\Partials.epub", "C:\\test\\decrypted_partials_new.epub");




           

            //System.Console.WriteLine(base64DerContent);
            //derContent = Convert.FromBase64String(base64DerContent);

            //var cipher = DecodeRSAPrivateKey(derContent);



            //Byte[] bookkey_data;    
            //var bookkey = Utilities.DecodeBase64("e1algxNK5vfiLQmN42bQf9CHJnRGH06w13P+ObHx5U7XJWbCsh9HKclXX88b2peEG4U3K4WC+dSNGLEPe8d3bPwxlBOYXVgsAHKLrgD7gXJDOG+gMawUsUlVx+hWPESITHXDscbcM6zASUuIWGtPkJw3r00MwJy9ZzYqfr2OiJg=",out bookkey_data);

            //Byte[] raw = cipher.Decrypt(bookkey_data, false);
            //string hex = BitConverter.ToString(raw);
            //System.Console.WriteLine("Decrypted: " + hex);
            //System.Console.WriteLine("Length:" + raw.Length);

            ////var bookkey = "e1algxNK5vfiLQmN42bQf9CHJnRGH06w13";

            //    IAsymmetricBlockCipher cipher = new RsaEngine();
            //    //RSAKeyPairGenerator generates the RSA Key pair based on the random number and strength of key required


            //RsaKeyParameters privParameters = new RsaPrivateCrtKeyParameters(new BigInteger(Modulus),  new BigInteger(Exponent), new BigInteger(D),null, null, null, null, null);


            //    IAsymmetricBlockCipher eng = new Pkcs1Encoding(new RsaEngine());
            //    eng.Init(false, privParameters);

            //    var encdata = eng.ProcessBlock(bookkey_data, 0, bookkey_data.Length);
            //    string result = Encoding.UTF8.GetString(encdata);
            //System.Console.WriteLine(result);

            //    //Pass the data to DECRYPT, the private key information  
            //    //(using RSACryptoServiceProvider.ExportParameters(true), 
            //    //and a boolean flag specifying no OAEP padding.
            //    //decryptedData = Crypto.RSADecrypt(encryptedData, RSA.ExportParameters(true), false);

            //    //Display the decrypted plaintext to the console. 
            //    //Console.WriteLine("Decrypted plaintext: {0}", ByteConverter.GetString(decryptedData));

            System.Console.ReadLine();

        }




    }
}
