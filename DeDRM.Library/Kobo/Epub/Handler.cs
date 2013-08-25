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
using Ionic.Zip;
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

        public override void RemoveDrm(String inputZipFilePath, String outputZipFilePath)
        {
            this.InputZipFilePath = inputZipFilePath;
            this.OutputZipFilePath = outputZipFilePath;
            using (ZipFile inputZip = ZipFile.Read(inputZipFilePath))
            {

                //ensure that book has DRM
                Constants.DRMType drmType;

                EpubHandler.DetectDrm(inputZip, out drmType);
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
                    encryptionXml.Root.Elements(encryptionns + "EncryptedData").Elements(encryptionns + "CipherData").Elements(encryptionns + "CipherReference").Attributes("URI").Select(x => x.Value.ToLowerInvariant()).ToList();//"/CipherData/CipherReference");

                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                using(ZipFile outputZipFile = new ZipFile())
                {
                    //outputZipFile.UseUnicodeAsNecessary = true; //ensure the file names use unicode names?
                    //outputZipFile.Encryption = EncryptionAlgorithm.None; //the file cannot be encrypted
                    //outputZipFile.CompressionLevel = CompressionLevel.None; //the file cannot be compressed
                    //outputZipFile.EmitTimesInWindowsFormatWhenSaving = false;

                    aes.Mode = CipherMode.CBC;
                    aes.Key = bookkey_plaintext_bytes;
                    aes.IV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

                    EpubAesDecrypter epubAesDecryptor = new EpubAesDecrypter(inputZip, aes, encryptedFiles);

                    // Create a decrytor to perform the stream transform.
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    //add the mimetype file manually
                    var mimetypeFile = inputZip["mimetype"];
                    using (var mimetypeReader = mimetypeFile.OpenReader())
                    {
                        Byte[] mimetypeContent = new byte[mimetypeReader.Length];
                        mimetypeReader.Read(mimetypeContent,0, mimetypeContent.Length);
                        var e = outputZipFile.AddEntry("mimetype", mimetypeContent);
                        e.EmitTimesInWindowsFormatWhenSaving = false;
                        e.CompressionLevel = CompressionLevel.None;
                    }
                    
                    foreach (var zipEntry in inputZip)
                    {
                        //Ignore specific unencypted files. //http://www.idpf.org/epub/30/spec/epub30-ocf.html#sec-container-metainf-encryption.xml
                        if ((String.Compare(zipEntry.FileName, "mimetype", true) == 0) ||
                            (String.Compare(zipEntry.FileName, "META-INF/rights.xml", true) == 0) ||
                            (String.Compare(zipEntry.FileName, "META-INF/encryption.xml", true) == 0))
                        {
                            //these files should not be included or will be manually added. 
                            continue;
                            
                        }
                        outputZipFile.AddEntry(zipEntry.FileName, epubAesDecryptor.WriteEntry);
                        
                    }
                    //add the mimetype manually


                    outputZipFile.Save(OutputZipFilePath);

                }
            }
            
        }
    }
    

}
