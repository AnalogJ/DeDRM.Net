//using System;
//using System.Collections.Generic;
//using System.Diagnostics;
//using System.IO;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;
//using System.Xml;
//using System.Xml.Linq;
//using DeDRM.Library.Base;
//using Ionic.Zip;

//namespace DeDRM.Library.Apple.Epub
//{
//    public class iBook : EpubHandler
//    {
//        public iBook() { }

//        override public void RemoveDrm(String output)
//        {
//            return;
//        }

//        /** Removes the DRM from f, writes the result to g, and returns true.
//    If no DRM is found, g is not written and it returns false. */
//        public static void RemoveDrm(FileStream f, out FileStream g)
//        {
//            Dictionary<long, Cipher> ciphers = getCiphers(f, null /* TODO */);
//            if (ciphers == null || ciphers.Count() == 0)
//            {
//                throw new Exception("Could not find decryption ciphers");
//                return;
//            }
//            unDrm(f, out g, ciphers);
//            return;
//        }

//        public static void unDrm(FileStream f, out FileStream g, Dictionary<long, Cipher> trak_ciphers)
//        {
//            Debug.WriteLine("removing drm " + f + " -> " + g);
//            Debug.Assert(trak_ciphers.Count() > 0);
//            using (ZipFile inputZip = ZipFile.Read(f))
//            using (ZipOutputStream outputZip = new ZipOutputStream(g))
//            {
//                copyOrDecryptZipEntries(inputZip, outputZip, trak_ciphers);
//            }


//        }
//        private static void copyOrDecryptZipEntries(ZipFile inputZip, ZipOutputStream outputZip, Dictionary<long, Cipher> ciphersById) {
//         int B = 0x8000; // encryption is done in chunks of this size
//        byte[] buf = new byte[B];
    
//        // read encryption.xml, get list of files to be decrypted
//        Dictionary<String,Cipher> ciphersByName = new Dictionary<String, Cipher>();
//        ZipEntry e = inputZip["META-INF/encryption.xml"];
//        if (e == null) throw new FileNotFoundException("no META-INF/encryption.xml file");
//        XDocument d = XDocument.Load(e.InputStream);
//            XNamespace enc = "http://www.w3.org/2001/04/xmlenc#";
//            XNamespace ds = "http://www.w3.org/2000/09/xmldsig#";
//    foreach (XElement encryptedFile in d.Elements(enc + "EncryptedData"))
//    {
//        String method = encryptedFile.Element(enc + "EncryptionMethod").Attribute("Algorithm").Value;
//      if (!method.Equals("http://itunes.apple.com/dataenc")) continue;

//      long keyId = long.Parse(encryptedFile.Element(ds +"KeyInfo").Element(ds + "KeyName").Value);
//      String file = Uri.UnescapeDataString(encryptedFile.Element(enc+ "CipherData").Element(enc+ "CipherReference").Attribute("URI").Value);
//      Cipher c = ciphersById[keyId];
//      if (c == null) throw new Exception("sinf key " + keyId + " not found");
//        ciphersByName[file] = c;
//        encryptedFile.Remove();
//    }
    
//    // loop through each entry, skipping, copying, or decrypting as appropriate.
//    ICollection<ZipEntry> entryList = inputZip.Entries;
//    foreach (ZipEntry in_e in entryList) {
//      //ZipEntry in_e = entryList.nextElement();
//        String in_e_FileName = in_e.FileName;
//      if (in_e_FileName.Equals("META-INF/sinf.xml") ||
//          (in_e_FileName.Equals("META-INF/encryption.xml") && d.Elements(enc + "EncryptedData").Count() == 0) ||
//          in_e_FileName.Equals("META-INF/signatures.xml")) { // TODO: redo signatures for unencrypted content
//        Debug.WriteLine("skipping " + in_e_FileName);
//          //files to leave untouched. 
//        continue;
//      }
//      //ZipEntry out_e = new ZipEntry();
//      //out_e.FileName = in_e_FileName;
//      //out_e.CreationTime = in_e.CreationTime;
//      if (in_e_FileName.Equals("mimetype",StringComparison.InvariantCultureIgnoreCase)) { 
//          // mimetype must not be deflated
//        //leave untouched. 
//      }

//      if (in_e_FileName.Equals("META-INF/encryption.xml")) {
//        // write out modified encryption.xml
//        //Transformer transformer = TransformerFactory.newInstance().newTransformer();
//        //transformer.transform(new DOMSource(d), new StreamResult(out));
//        //remove the encryption.xml
//            inputZip.RemoveEntry(in_e);

//          MemoryStream dMemoryStream = new MemoryStream();
//            XmlWriterSettings xws = new XmlWriterSettings();
//            xws.OmitXmlDeclaration = true;
//            xws.Indent = true;

//            using (XmlWriter xw = XmlWriter.Create(dMemoryStream, xws))
//            {
//            d.WriteTo(xw);
//            }


//          inputZip.AddEntry("META-INF/encryption.xml", dMemoryStream);
            
//        continue;
//      }
//      Stream i = in_e.InputStream;
//      if (in_e_FileName.Equals("iTunesMetadata.plist")) {
//        // remove drm key/value
//        ByteArrayOutputStream s = new ByteArrayOutputStream();
//        BufferedReader r = new BufferedReader(new InputStreamReader(i));
//        Writer w = new OutputStreamWriter(s);
//        while (true) {
//          String line = r.readLine();
//          if (line == null) break;
//          if (line.contains("<key>drmVersionNumber</key>")) {
//            r.readLine();
//          } else {
//            w.write(line + "\n");
//          }
//        }
//        w.flush();
//        i = new ByteArrayInputStream(s.toByteArray());
//      }
//      Cipher c = ciphersByName.get(in_e.getName());
//      if (c == null) {
//        Debug.WriteLine("copying " + in_e_FileName);
//        while (true) {
//          int cnt = i.read(buf);
//          if (cnt < 0) break;
//          out.write(buf, 0, cnt);
//        }
//      } else {
//        Debug.WriteLine("decrypting " + in_e.FileName);
//        while (true) {
//          // read up to B bytes
//          int cnt = 0;
//          while (cnt < B) {
//            int n = i.read(buf, cnt, B - cnt);
//            if (n < 0) break;
//            cnt += n;
//          }
//          if (cnt == 0) break;
          
//          // decrypt it
//          try {
//            c.doFinal(buf, 0, cnt & ~0xf, buf, 0);
//          } catch (GeneralSecurityException ex) {
//            throw new RuntimeException(ex);
//          }
//          out.write(buf, 0, cnt);
//        }
//      }
//    }
//  }



//    }
//}
