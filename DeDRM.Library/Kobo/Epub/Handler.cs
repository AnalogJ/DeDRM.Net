using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml.XPath;
using DeDRM.Library.Base;
using Ionic.Zlib;

namespace DeDRM.Library.Kobo.Epub
{
    /// <summary>
    /// Based on ineptepub.py file.
    /// </summary>
    public class Handler : EpubHandler
    {
        public Byte[] DerContent { get; set; }
        public Handler(Byte[] derContent)
        {
            //Adobe Adept DER-encoded files
            DerContent = derContent;


        }

        private void GenerateBookDecryptionKey(String encryptedKey, out Byte[] bookkey_plaintext_bytes)
        {
            //Create a new instance of RSACryptoServiceProvider to generate 
            //public and private key data. 
            bookkey_plaintext_bytes = null;
            using (var rsa = Crypto.Crypto.DecodeRSAPrivateKey(DerContent))
            {

                var bookkey_ciphertext_bytes = Convert.FromBase64String(encryptedKey);

                bookkey_plaintext_bytes = rsa.Decrypt(bookkey_ciphertext_bytes, false);
                string hex = BitConverter.ToString(bookkey_plaintext_bytes);
                System.Console.WriteLine("Decrypted: " + hex);

            }
        }

        public override void RemoveDrm(string outputFile)
        {
            //ensure that book has DRM
            Constants.DRMType drmType;

            this.DetectDrm(out drmType);
            if (drmType == Constants.DRMType.None)
            {
                throw new Exception("No Encryption Found");
            }

            var rightsFile = inputZip["META-INF/rights.xml"];
            XDocument rightsXml = XDocument.Load(rightsFile.OpenReader());
            var encryptedKey = rightsXml.Descendants(adeptns + "encryptedKey").FirstOrDefault();

            if (encryptedKey == null || encryptedKey.Value.Length != 172)
            {
                throw new Exception("This is not a secure Adobe Adept ePub");
            }

            Byte[] bookkey_plaintext_bytes;
            //Decrypt the bookkey using the encrypted key stored in the book. 
            GenerateBookDecryptionKey(encryptedKey.Value, out bookkey_plaintext_bytes);


            var encryptionFile = inputZip["META-INF/encryption.xml"];
            XDocument encryptionXml = XDocument.Load(encryptionFile.OpenReader());
            //find a list of files that are encrypted in the epub.
            var encryptedFiles =
                encryptionXml.Root.Elements(encryptionns + "EncryptedData").Elements(encryptionns + "CipherData").Elements(encryptionns + "CipherReference").Attributes("URI").Select(x => x.Value.ToLowerInvariant());//"/CipherData/CipherReference");

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {

                aes.Mode = CipherMode.CBC;
                aes.Key = bookkey_plaintext_bytes;
                aes.IV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);


                foreach (var zipEntry in inputZip)
                {
                    //Ignore specific unencypted files. //http://www.idpf.org/epub/30/spec/epub30-ocf.html#sec-container-metainf-encryption.xml
                    if ((String.Compare(zipEntry.FileName, "mimetype", true) == 0) ||
                        (String.Compare(zipEntry.FileName, "META-INF/rights.xml") == 0) ||
                        (String.Compare(zipEntry.FileName, "META-INF/container.xml") == 0) ||
                        (String.Compare(zipEntry.FileName, "META-INF/manifest.xml") == 0) ||
                        (String.Compare(zipEntry.FileName, "META-INF/signatures.xml") == 0) ||
                        (String.Compare(zipEntry.FileName, "META-INF/rights.xml") == 0) ||
                        (String.Compare(zipEntry.FileName, "META-INF/encryption.xml") == 0))
                    {
                        continue;
                    }

                    try
                    {
                        if (encryptedFiles.Contains(zipEntry.FileName.ToLowerInvariant()))
                        {
                            //decrypt files. 
                            byte[] plainBytes;
                            using (var msDecrypt = zipEntry.OpenReader())
                            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                            {

                                //copy the decrypted bytes into a plainBytes array. Makesure that only the required bytes are copied. 
                                
                                using (var memoryStream = new MemoryStream())
                                {
                                    
                                    csDecrypt.CopyTo(memoryStream);
                                    //translated from: self._aes.decrypt(data)[16:] --skip the first 16 bytes.
                                    plainBytes = memoryStream.ToArray();

                                    //translated from: data = data[:-ord(data[-1])]
                                    //the last byte has a number of extra padding bytes that were added and now need to be removed. 
                                    byte extraPaddingCount = plainBytes.Last();
                                    plainBytes = plainBytes.Skip(16).Take(plainBytes.Length - extraPaddingCount).ToArray();
                                }
                            }

                            //Decompress using gzip
                            using (var plainZippedStream = new MemoryStream(plainBytes))
                            using (var decompressor = new Ionic.Zlib.DeflateStream(plainZippedStream, CompressionMode.Decompress))
                            using (var plainStream = new MemoryStream())
                            {
                                decompressor.CopyTo(plainStream);
                                String output = Encoding.UTF8.GetString(plainStream.ToArray());

                                Console.WriteLine(output);
                            }




                        }



                    }
                    catch (Exception ex)
                    {
                        //do nothing, gotta catch em all.
                        throw ex;
                    }


                }
            }


        }



    }
}
