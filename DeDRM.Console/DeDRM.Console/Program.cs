using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
            var cipher = DecodeRSAPrivateKey(derContent);
            

            
            Byte[] bookkey_data;    
            var bookkey = Utilities.DecodeBase64("e1algxNK5vfiLQmN42bQf9CHJnRGH06w13P+ObHx5U7XJWbCsh9HKclXX88b2peEG4U3K4WC+dSNGLEPe8d3bPwxlBOYXVgsAHKLrgD7gXJDOG+gMawUsUlVx+hWPESITHXDscbcM6zASUuIWGtPkJw3r00MwJy9ZzYqfr2OiJg=",out bookkey_data);
             
            Byte[] raw = cipher.Decrypt(bookkey_data, false);
            string hex = BitConverter.ToString(raw);
            System.Console.WriteLine("Decrypted: " + hex);
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



        //------- Parses binary ans.1 RSA private key; returns RSACryptoServiceProvider  ---
        public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
        {
            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

            // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
            MemoryStream mem = new MemoryStream(privkey);
            BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;
            int elems = 0;
            try
            {
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();        //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();       //advance 2 bytes
                else
                    return null;

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102) //version number
                    return null;
                bt = binr.ReadByte();
                if (bt != 0x00)
                    return null;


                //------  all private key components are Integer sequences ----
                elems = GetIntegerSize(binr);
                MODULUS = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                E = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                D = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                P = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                Q = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DP = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DQ = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                IQ = binr.ReadBytes(elems);

                System.Console.WriteLine("showing components ..");
                if (true)
                {
                    System.Console.WriteLine("\nModulus", MODULUS);
                    System.Console.WriteLine("\nExponent", E);
                    System.Console.WriteLine("\nD", D);
                    System.Console.WriteLine("\nP", P);
                    System.Console.WriteLine("\nQ", Q);
                    System.Console.WriteLine("\nDP", DP);
                    System.Console.WriteLine("\nDQ", DQ);
                    System.Console.WriteLine("\nIQ", IQ);
                }

                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSAParameters RSAparams = new RSAParameters();
                RSAparams.Modulus = MODULUS;
                RSAparams.Exponent = E;
                RSAparams.D = D;
                RSAparams.P = P;
                RSAparams.Q = Q;
                RSAparams.DP = DP;
                RSAparams.DQ = DQ;
                RSAparams.InverseQ = IQ;
                RSA.ImportParameters(RSAparams);
                return RSA;
            }
            catch (Exception)
            {
                return null;
            }
            finally
            {
                binr.Close();
            }
        }
        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)		//expect integer
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();	// data size in next byte
            else
                if (bt == 0x82)
                {
                    highbyte = binr.ReadByte();	// data size in next 2 bytes
                    lowbyte = binr.ReadByte();
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    count = BitConverter.ToInt32(modint, 0);
                }
                else
                {
                    count = bt;		// we already have the data size
                }



            while (binr.ReadByte() == 0x00)
            {	//remove high order zeros in data
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);		//last ReadByte wasn't a removed zero, so back up a byte
            return count;
        }
    }
}
