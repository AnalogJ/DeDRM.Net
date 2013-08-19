//using System;
//using System.Collections.Generic;
//using System.ComponentModel;
//using System.Linq;
//using System.Security.Cryptography;
//using System.Text;
//using System.Threading.Tasks;
//using System.Xml.Linq;
//using DeDRM.Library.Base;

//namespace DeDRM.Library.Kobo.Epub
//{
//    /// <summary>
//    /// Based on ineptepub.py file.
//    /// </summary>
//    public class Handler : EpubHandler
//    {
//        public Byte[] DerContent { get; set; }
//        public Handler(Byte[] derContent)
//        {
//            //Adobe Adept DER-encoded files
//            DerContent = derContent;

//            AsnEncodedData data = new AsnEncodedData(derContent);

//        }

//        public override void RemoveDrm(string outputFile)
//        {
//            //ensure that book has DRM
//            Constants.DRMType drmType;

//            this.DetectDrm(out drmType);
//            if (drmType == Constants.DRMType.None)
//            {
//                throw new Exception("No Encryption Found");
//            }

//            var rightsFile = inputZip["META-INF/rights.xml"];
//            XDocument rightsXml = XDocument.Load(rightsFile.InputStream);
//            var encryptedKey = rightsXml.Descendants(adeptns + "encryptedKey").FirstOrDefault();

//            if (encryptedKey == null || encryptedKey.Value.Length != 172)
//            {
//                throw new Exception("This is not a secure Adobe Adept ePub");
//            }
            
//            //Create a new instance of RSACryptoServiceProvider to generate 
//            //public and private key data. 
//            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
//            {

//                var bookkey = Utilities.DecodeBase64(encryptedKey);
//                //Pass the data to DECRYPT, the private key information  
//                //(using RSACryptoServiceProvider.ExportParameters(true), 
//                //and a boolean flag specifying no OAEP padding.
//                decryptedData = Crypto.RSADecrypt(encryptedData, RSA.ExportParameters(true), false);

//                //Display the decrypted plaintext to the console. 
//                //Console.WriteLine("Decrypted plaintext: {0}", ByteConverter.GetString(decryptedData));
//            }

//            foreach (var zipEntry in inputZip)
//            {
//                //Ignore specific unencypted files.
//                if ((String.Compare(zipEntry.FileName, "mimetype", true) == 0) ||
//                    (String.Compare(zipEntry.FileName, "META-INF/rights.xml") == 0) ||
//                    (String.Compare(zipEntry.FileName, "META-INF/encryption.xml") == 0))
//                {
//                    continue;
//                }

//                try
//                {




//                }
//                catch (Exception ex)
//                {
//                    //do nothing, gotta catch em all.
//                }


//            }

//        }



//    }
//}
