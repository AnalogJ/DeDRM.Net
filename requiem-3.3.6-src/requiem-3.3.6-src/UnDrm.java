import java.util.*;
import java.util.logging.*;
import java.util.zip.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.w3c.dom.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;

/**
   This class is used to remove the drm from a file.  There are two
   main entry points:
     getTrackCiphers - figures out all the information required
                       to decrypt a file.
     unDrm - uses the information returned by getTrackCiphers to
             to actually remove the DRM.
   These methods are split into two because most errors will happen
   during getTrackCiphers.  The latter call is unlikely to fail
   (with the notable exception of disk full errors).
 */
class UnDrm {
  private static final Logger log = Logger.getLogger(UnDrm.class.getName());

  private static abstract class Transform {
    abstract void transform(byte[] data, int off, int len);
  }
  
  private static class AtomTransform extends Transform {
    byte[] data;
    AtomTransform(String type) {
      this.data = new byte[4];
      for (int i = 0; i < 4; i++) data[i] = (byte)type.charAt(i);
    }
    void transform(byte[] data, int off, int len) {
      assert len == 4 : len;
      System.arraycopy(this.data, 0, data, off, 4);
    }
  }
  
  private static class AESTransform extends Transform {
    Cipher cipher;
    AESTransform(Cipher cipher) {
      this.cipher = cipher;
    }
    void transform(byte[] data, int off, int len) {
      try {
        cipher.doFinal(data, off, len & ~0xf, data, off);
      } catch (GeneralSecurityException e) {
        throw new RuntimeException(e);
      }
    }
  }
  
  private static class AESVideoTransform extends Transform {
    Cipher cipher;
    int init;
    int crypt_size;
    int uncrypt_size;
    AESVideoTransform(Cipher cipher, int init, int crypt_size, int uncrypt_size) {
      this.cipher = cipher;
      this.init = init;
      this.crypt_size = crypt_size;
      this.uncrypt_size = uncrypt_size;
    }
    void transform(byte[] data, int off, int len) {
      try {
        ByteArrayOutputStream x = new ByteArrayOutputStream();
        for (int i = init; i < len; i += crypt_size + uncrypt_size) {
          x.write(data, off + i, Math.min(len - i, crypt_size));
        }
        byte[] buf = x.toByteArray();
        cipher.doFinal(buf, 0, buf.length & ~0xf, buf, 0);
        ByteArrayInputStream y = new ByteArrayInputStream(buf);
        for (int i = init; i < len; i += crypt_size + uncrypt_size) {
          y.read(data, off + i, Math.min(len - i, crypt_size));
        }
      } catch (GeneralSecurityException e) {
        throw new RuntimeException(e);
      }
    }
  }
  
  // a transform at a particular place in the file
  private static class TransformInstance implements Comparable<TransformInstance> {
    long offset;
    int size;
    Transform transform;
    
    TransformInstance(long offset, int size, Transform transform) {
      this.offset = offset;
      this.size = size;
      this.transform = transform;
    }
    
    public int compareTo(TransformInstance t) { // sorts smallest offset first
      if (offset < t.offset) return -1;
      if (offset > t.offset) return 1;
      return 0;
    }
  }
  
  private static Cipher getTrackCipher(byte[] priv, SecretKeySpec privKey, IvParameterSpec privIv) {
    try {
      // decrypt priv
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, privKey, privIv);
      cipher.doFinal(priv, 0, priv.length & ~0xf, priv, 0);
      Util.printBuf("decrypted priv", priv);

      // check decryption
      if (new String(priv, 0, 4).equals("itun") &&
	  new String(priv, 20, 4).equals("key ") &&
	  new String(priv, 44, 4).equals("iviv")) {
	// return a cipher initialized from the track key and iv
	Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
	c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(priv, 24, 16, "AES"), new IvParameterSpec(priv, 48, 16));
	return c;
      } else {
	return null;
      }
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }
  
  private static Cipher getTrackCipher(Mp4.Atom schi, AtomRandomAccessFile f, Notifier notifier) throws Exception {
    Mp4.Atom userAtom = schi.find("user");
    Mp4.Atom keyAtom = schi.find("key ");
    Mp4.Atom ivivAtom = schi.find("iviv");
    Mp4.Atom nameAtom = schi.find("name");
    Mp4.Atom privAtom = schi.find("priv");
    
    int userId = f.readInt(userAtom.offset + 8);
    int keyId = f.readInt(keyAtom.offset + 8);
    byte[] iviv = f.readFully(ivivAtom.offset + 8, 16);
    byte[] name = f.readFully(nameAtom.offset + 8, nameAtom.size - 8);
    byte[] priv = f.readFully(privAtom.offset + 8, privAtom.size - 8);
    
    // compute iv for priv decrypt
    MessageDigest md = MessageDigest.getInstance("MD5");
    for (int i = 0; i < name.length; i++) {
      if (name[i] == 0) break;
      md.update(name[i]);
    }
    md.update(iviv);
    IvParameterSpec privIv = new IvParameterSpec(md.digest());
    Util.printBuf("priv iv", privIv.getIV());
    
    // try (potentially multiple) priv decryption keys
    for (SecretKeySpec privKey : KeyCache.getKey(userId, keyId)) {
      Cipher c = getTrackCipher(priv, privKey, privIv);
      if (c != null) {
        // tell the key cache that this key worked
        KeyCache.verifyKey(userId, keyId, privKey);
        return c;
      } else {
        KeyCache.badKey(userId, keyId, privKey);
      }
    }
    log.info("key " + Integer.toHexString(userId) + "/" + Integer.toHexString(keyId) + " not found in cache");
    // call to gather more keys, try again
    ExtractKeys.extractKeys(userId, notifier);
    for (SecretKeySpec privKey : KeyCache.getKey(userId, keyId)) {
      Cipher c = getTrackCipher(priv, privKey, privIv);
      if (c != null) {
        // tell the key cache that this key worked
        KeyCache.verifyKey(userId, keyId, privKey);
        return c;
      } else {
        KeyCache.badKey(userId, keyId, privKey);
      }
    }
    
    if (KeyCache.isUndecodableKey(userId, keyId)) {
      throw new RuntimeException("key type not known - Requiem is unable to process this file");
    }
    throw new RuntimeException("Key not found.  Can iTunes play this file?");
  }
  
  // returns a pointer to mdia.minf.stbl.stsd.(drms|drmi|p608)
  static Mp4.Atom getTrackDrmAtom(Mp4.Atom trak) {
    Mp4.Atom stsd = trak.find("mdia.minf.stbl.stsd");
    if (stsd == null) return null;
    Mp4.Atom drm = stsd.find("drms");
    if (drm == null) drm = stsd.find("drmi");
    if (drm == null) drm = stsd.find("p608");
    return drm;
  }
  
  // returns a map from the track (offset in file of the trak atom) to the cipher
  // used to decrypt that track.
  static Map<Long,Cipher> getTrackCiphers(File file, Notifier notifier) throws Exception {
    Map<Long,Cipher> ciphers = new HashMap<Long,Cipher>();
    
    // find cipher for each trak
    Mp4.Atom mp4 = Mp4.parse(file);
    AtomRandomAccessFile r = new AtomRandomAccessFile(file, "r");
    Mp4.Atom moov = mp4.find("moov");
    for (Mp4.Atom trak : moov.children) {
      if (!trak.type.equals("trak")) continue;
      Mp4.Atom drm = getTrackDrmAtom(trak);
      if (drm == null) continue; // no DRM
      Mp4.Atom schi = drm.find("sinf.schi");
      Cipher c = getTrackCipher(schi, r, notifier);
      ciphers.put(trak.offset, c);
    }
    r.close();
    return ciphers;
  }

  // returns the child of e with the given tag.  Throws an exception if it can't be found
  // or if it isn't unique.
  private static Element getChild(Element e, String tag) {
    List<Element> children = getChildren(e, tag);
    if (children.size() == 0) throw new RuntimeException("tag " + tag + " not found");
    if (children.size() > 1) throw new RuntimeException("found duplicate tag " + tag);
    return children.get(0);
  }
  // returns all children of e with the given tag.
  private static List<Element> getChildren(Element e, String tag) {
    List<Element> result = new ArrayList<Element>();
    NodeList list = e.getChildNodes();
    for (int i = 0; i < list.getLength(); i++) {
      if (!(list.item(i) instanceof Element)) continue;
      Element f = (Element)list.item(i);
      if (f.getNodeName().equals(tag)) result.add(f);
    }
    return result;
  }

  private static boolean checkEBookKey(File f, long sId, Cipher c) throws Exception {
    // TODO: there's probably a better way to do this.
    ZipFile z = new ZipFile(f);
    try {
      ZipEntry e = z.getEntry("META-INF/encryption.xml");
      if (e == null) throw new RuntimeException("no META-INF/encryption.xml file");
      Document d = Util.parseXml(z.getInputStream(e));
      for (Element encryptedFile : getChildren(d.getDocumentElement(), "e:EncryptedData")) {
        String method = getChild(encryptedFile, "e:EncryptionMethod").getAttribute("Algorithm");
        if (!method.equals("http://itunes.apple.com/dataenc")) continue;
        long keyId = Long.parseLong(getChild(getChild(encryptedFile, "d:KeyInfo"), "d:KeyName").getTextContent());
        String file = URLDecoder.decode(getChild(getChild(encryptedFile, "e:CipherData"), "e:CipherReference").getAttribute("URI"), "UTF-8");
        
        if (keyId != sId) continue;
        
        // decrypt first bit of file, look for particular plaintexts to see if decryption was successful
        ZipEntry x = z.getEntry(file);
        if (x == null) {
          log.warning("ebook entry " + file + " not found");
          continue;
        }
        byte[] first_chunk = Util.read(z.getInputStream(x), 64);
        c.doFinal(first_chunk, 0, first_chunk.length & ~0xf, first_chunk, 0);
        String s = new String(first_chunk, "ISO-8859-1");
        if (s.startsWith("\u0089PNG\r\n\u001a\n")) return true;
        if (s.startsWith("GIF87a")) return true;
        if (s.startsWith("GIF89a")) return true;
        if (s.startsWith("\u00ff\u00d8\u00ff\u00e0\u0000\u0010JFIF\u0000")) return true;
        if (s.contains("<?xml ")) return true;
        if (s.contains("version=")) return true;
        if (s.contains("<!DOCTYPE")) return true;
        if (s.contains("<html ")) return true;
        if (s.contains("<html>")) return true;
      }
      return false;
    } finally {
      z.close();
    }
  }
  
  private static Cipher decryptSinfCipher(SecretKeySpec userKey, IvParameterSpec iv, byte[] encryptedKey) throws Exception {
    // decrypt key
    byte[] decryptedKey = new byte[16];
    Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, userKey);
    cipher.doFinal(encryptedKey, 0, 16, decryptedKey, 0);
    SecretKeySpec key = new SecretKeySpec(decryptedKey, "AES");
    Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
    c.init(Cipher.DECRYPT_MODE, key, iv);
    return c;
  }
  
  private static Cipher getSinfCipher(byte[] sinf, Notifier notifier, long sId, File f) throws Exception {
    Util.printBuf("sinf", sinf);
    DER.Atom a = DER.parse(sinf, 24);
    //a.print();
    if (a.encodedLength != sinf.length - 24) throw new RuntimeException("didn't use all of sinf " + a.encodedLength);
    DER.Atom keyinfo = a.child(1).child(0).child(2).child(1).child(0);
    DER.Atom b = DER.parse(keyinfo.data, 0);
    //b.print();
    
    Map<Integer,byte[]> versions = new HashMap<Integer,byte[]>();
    for (int j = 0; j < b.children.size(); j++) {
      DER.Atom c = b.child(j);
      int version = (c.child(0).data[0] & 0xff) * 0x100 + (c.child(1).data[0] & 0xff);
      versions.put(version, c.child(2).data);
    }
    
    // get userId, IV
    byte[] v101 = versions.get(0x101);
    if (v101 == null) throw new RuntimeException("can't find version 101");
    DER.Atom d = DER.parse(v101, 0);
    //d.print();
    int userId = Util.getInt(d.child(1).data);
    log.fine(String.format("user id %x", userId));
    IvParameterSpec iv = new IvParameterSpec(d.child(4).data);
    Util.printBuf("iv", iv.getIV());
    
    // get keyId, encrypted key
    byte[] v301 = versions.get(0x301);
    if (v301 == null) throw new RuntimeException("can't find version 301");
    int keyId = Util.getInt32(v301, 0);
    byte[] encryptedKey = new byte[16];
    System.arraycopy(v301, 4, encryptedKey, 0, 16);
    Util.printBuf("encrypted key", encryptedKey);
    
    // get user key to decrypt key
    for (SecretKeySpec userKey : KeyCache.getKey(userId, keyId)) {
      Cipher c = decryptSinfCipher(userKey, iv, encryptedKey);
      if (checkEBookKey(f, sId, c)) {
        KeyCache.verifyKey(userId, keyId, userKey);
        return c;
      } else {
        KeyCache.badKey(userId, keyId, userKey);
      }
    }
    log.info("key " + Integer.toHexString(userId) + "/" + Integer.toHexString(keyId) + " not found in cache");
    // call to gather more keys, try again
    ExtractKeys.extractKeys(userId, notifier);
    for (SecretKeySpec userKey : KeyCache.getKey(userId, keyId)) {
      Cipher c = decryptSinfCipher(userKey, iv, encryptedKey);
      if (checkEBookKey(f, sId, c)) {
        KeyCache.verifyKey(userId, keyId, userKey);
        return c;
      } else {
        KeyCache.badKey(userId, keyId, userKey);
      }
    }
    
    if (KeyCache.isUndecodableKey(userId, keyId)) {
      throw new RuntimeException("key type not known - Requiem is unable to process this file");
    }
    throw new RuntimeException("Key not found.  Can you read this book?");
  }
  
  static Map<Long,Cipher> getBookCiphers(InputStream sinf_file, Notifier notifier, File f) throws Exception {
    Map<Long,Cipher> ciphers = new HashMap<Long,Cipher>();
    Document d = Util.parseXml(sinf_file);
    NodeList sIdList = d.getElementsByTagName("fairplay:sID");
    NodeList sDataList = d.getElementsByTagName("fairplay:sData");
    if (sIdList.getLength() != sDataList.getLength()) throw new RuntimeException("sid and sdata different lengths");
    for (int i = 0; i < sIdList.getLength(); i++) {
      Element sIdElem = (Element)sIdList.item(i);
      Element sDataElem = (Element)sDataList.item(i);
      long sId = Long.parseLong(sIdElem.getTextContent());
      byte[] sData = Util.base64decode(sDataElem.getTextContent());
      Cipher c = getSinfCipher(sData, notifier, sId, f);
      ciphers.put(sId, c);
    }
    return ciphers;
  }

  static Map<Long,Cipher> getCiphers(File f, Notifier notifier) throws Exception {
    Map<Long,Cipher> ciphers = null;
    AtomRandomAccessFile r = new AtomRandomAccessFile(f, "r");
    try {
      int magic = r.readInt(0);
      if (magic == 0x504b0304) { // a zip file
        ZipFile z = new ZipFile(f);
        try {
          ZipEntry e = z.getEntry("META-INF/sinf.xml");
          if (e != null) { // protected epub
            ciphers = getBookCiphers(z.getInputStream(e), notifier, f);
          }
        } finally {
          z.close();
        }
      } else {
        String ftyp = r.readType(4);
        String kind = r.readType(8);
        if (ftyp.equals("ftyp") && (kind.equals("M4A ") || kind.equals("M4V ") || kind.equals("M4B "))) {
          // If we can't find a cipher, we'll get an exception from this call.
          ciphers = getTrackCiphers(f, notifier);
        }
      }
    } finally {
      r.close();
    }
    return ciphers;
  }

  // adds to transforms the items needed to decrypt the track.
  private static void deDrmTransforms(Mp4.Atom trak, Cipher cipher, AtomRandomAccessFile f, List<TransformInstance> transforms) throws IOException {
    Mp4.Atom drm = getTrackDrmAtom(trak);
    assert drm != null;
    Mp4.Atom sinf = drm.find("sinf");
    Mp4.Atom frma = sinf.find("frma");
    Mp4.Atom skcr = sinf.find("skcr");
    
    // neuter the sinf atom
    transforms.add(new TransformInstance(sinf.offset + 4, 4, new AtomTransform("pinf")));
    
    // frma contains the new name for drms (or drmi or p608)
    transforms.add(new TransformInstance(drm.offset + 4, 4, new AtomTransform(f.readType(frma.offset + 8))));
    
    Transform t;
    if (skcr == null) {
      t = new AESTransform(cipher);
    } else {
      t = new AESVideoTransform(cipher, f.readInt(skcr.offset + 8), f.readInt(skcr.offset + 12), f.readInt(skcr.offset + 16));
    }
    
    // decrypt track proper
    Mp4.Atom stbl = trak.find("mdia.minf.stbl");
    Mp4.Atom stsc = stbl.find("stsc");
    Mp4.Atom stsz = stbl.find("stsz");
    Mp4.Atom stco = stbl.find("stco");
    Mp4.Atom co64 = stbl.find("co64");
    
    // get sample size data
    int[] sample_sizes;
    {
      int fixed_sample_size = f.readInt(stsz.offset + 12);
      int nsamples = f.readInt(stsz.offset + 16);
      if (fixed_sample_size != 0) {
        sample_sizes = new int[nsamples];
        for (int i = 0; i < nsamples; i++) sample_sizes[i] = fixed_sample_size;
      } else {
        sample_sizes = f.readIntArray(stsz.offset + 20, nsamples);
      }
    }
    
    // get chunk offsets
    long[] chunk_offsets;
    {
      if (co64 != null) {
        int n = f.readInt(co64.offset + 12);
        chunk_offsets = f.readLongArray(co64.offset + 16, n);
      } else {
        int n = f.readInt(stco.offset + 12);
        chunk_offsets = new long[n];
        int[] x = f.readIntArray(stco.offset + 16, n);
        for (int i = 0; i < n; i++) chunk_offsets[i] = x[i] & 0xffffffffL;
      }
    }
    
    // get chunk group info
    int chunk_groups = f.readInt(stsc.offset + 12);
    int[] chunk_group_info = f.readIntArray(stsc.offset + 16, 3 * chunk_groups);
    
    // Loop through chunk groups, chunks, and samples, queueing a decrypt
    // request for each sample.
    int sample = 0;
    for (int chunk_group = 0; chunk_group < chunk_groups; chunk_group++) {
      int first_chunk = chunk_group_info[chunk_group * 3] - 1;
      int samples_per_chunk = chunk_group_info[chunk_group * 3 + 1];
      int chunks;
      if (chunk_group != chunk_groups - 1) {
        chunks = chunk_group_info[chunk_group * 3 + 3] - 1 - first_chunk;
      } else {
        chunks = chunk_offsets.length - first_chunk;
      }
      for (int chunk = first_chunk; chunk < first_chunk + chunks; chunk++) {
        long sample_offset = chunk_offsets[chunk];
        for (int i = 0; i < samples_per_chunk; i++, sample++) {
          int sample_size = sample_sizes[sample];
          transforms.add(new TransformInstance(sample_offset, sample_size, t));
          sample_offset += sample_size;
        }
      }
    }
  }
  
  private static void transformFile(File f, File g, List<TransformInstance> transforms) throws IOException {
    // sort transforms
    Collections.sort(transforms);
    
    // apply transforms while copying the file
    IOStream io = new IOStream(new FileInputStream(f), new FileOutputStream(g));
    for (TransformInstance t : transforms) {
      assert t.offset >= io.offset;
      io.skip(t.offset - io.offset);
      int p = io.process(t.size);
      t.transform.transform(io.buf, p, t.size);
    }
    io.skip(f.length() - io.offset);
    io.close();
  }
  
  // this is the main routine for ebook decryption.  It copies zip file to zip file, decrypting
  // any zip entries listed in the encryption.xml file using the ciphers in ciphersById.
  private static void copyOrDecryptZipEntries(ZipFile in, ZipOutputStream out, Map<Long,Cipher> ciphersById) throws Exception {
    final int B = 0x8000; // encryption is done in chunks of this size
    byte[] buf = new byte[B];
    
    // read encryption.xml, get list of files to be decrypted
    Map<String,Cipher> ciphersByName = new HashMap<String,Cipher>();
    ZipEntry e = in.getEntry("META-INF/encryption.xml");
    if (e == null) throw new RuntimeException("no META-INF/encryption.xml file");
    Document d = Util.parseXml(in.getInputStream(e));
    for (Element encryptedFile : getChildren(d.getDocumentElement(), "e:EncryptedData")) {
      String method = getChild(encryptedFile, "e:EncryptionMethod").getAttribute("Algorithm");
      if (!method.equals("http://itunes.apple.com/dataenc")) continue;
      long keyId = Long.parseLong(getChild(getChild(encryptedFile, "d:KeyInfo"), "d:KeyName").getTextContent());
      String file = URLDecoder.decode(getChild(getChild(encryptedFile, "e:CipherData"), "e:CipherReference").getAttribute("URI"), "UTF-8");
      Cipher c = ciphersById.get(keyId);
      if (c == null) throw new RuntimeException("sinf key " + keyId + " not found");
      ciphersByName.put(file, c);
      d.getDocumentElement().removeChild(encryptedFile);
    }
    
    // loop through each entry, skipping, copying, or decrypting as appropriate.
    Enumeration<? extends ZipEntry> entryList = in.entries();
    while (entryList.hasMoreElements()) {
      ZipEntry in_e = entryList.nextElement();
      if (in_e.getName().equals("META-INF/sinf.xml") ||
          (in_e.getName().equals("META-INF/encryption.xml") && getChildren(d.getDocumentElement(), "e:EncryptedData").size() == 0) ||
          in_e.getName().equals("META-INF/signatures.xml")) { // TODO: redo signatures for unencrypted content
        log.fine("skipping " + in_e.getName());
        continue;
      }
      ZipEntry out_e = new ZipEntry(in_e.getName());
      out_e.setTime(in_e.getTime());
      if (in_e.getName().equals("mimetype")) { // mimetype must not be deflated
        out_e.setMethod(ZipEntry.STORED);
        out_e.setCompressedSize(in_e.getSize());
        out_e.setSize(in_e.getSize());
        out_e.setCrc(in_e.getCrc());
      }
      out.putNextEntry(out_e);
      if (in_e.getName().equals("META-INF/encryption.xml")) {
        // write out modified encryption.xml
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(d), new StreamResult(out));
        continue;
      }
      InputStream i = in.getInputStream(in_e);
      if (in_e.getName().equals("iTunesMetadata.plist")) {
        // remove drm key/value
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        BufferedReader r = new BufferedReader(new InputStreamReader(i));
        Writer w = new OutputStreamWriter(s);
        while (true) {
          String line = r.readLine();
          if (line == null) break;
          if (line.contains("<key>drmVersionNumber</key>")) {
            r.readLine();
          } else {
            w.write(line + "\n");
          }
        }
        w.flush();
        i = new ByteArrayInputStream(s.toByteArray());
      }
      Cipher c = ciphersByName.get(in_e.getName());
      if (c == null) {
        log.fine("copying " + in_e.getName());
        while (true) {
          int cnt = i.read(buf);
          if (cnt < 0) break;
          out.write(buf, 0, cnt);
        }
      } else {
        log.fine("decrypting " + in_e.getName());
        while (true) {
          // read up to B bytes
          int cnt = 0;
          while (cnt < B) {
            int n = i.read(buf, cnt, B - cnt);
            if (n < 0) break;
            cnt += n;
          }
          if (cnt == 0) break;
          
          // decrypt it
          try {
            c.doFinal(buf, 0, cnt & ~0xf, buf, 0);
          } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
          }
          out.write(buf, 0, cnt);
        }
      }
    }
  }
  
  public static void unDrm(File f, File g, Map<Long,Cipher> trak_ciphers) throws Exception {
    log.info("removing drm " + f + " -> " + g);
    assert trak_ciphers.size() > 0;
    AtomRandomAccessFile r = new AtomRandomAccessFile(f, "r");
    int magic = r.readInt(0);
    if (magic == 0x504b0304) { // a zip file
      ZipFile in = new ZipFile(f);
      ZipOutputStream out = new ZipOutputStream(new FileOutputStream(g));
      copyOrDecryptZipEntries(in, out, trak_ciphers);
      in.close();
      out.close();
    } else {
      // build a list of decryption transforms
      Mp4.Atom mp4 = Mp4.parse(f);
      Mp4.Atom moov = mp4.find("moov");
      List<TransformInstance> transforms = new ArrayList<TransformInstance>();
      for (Mp4.Atom trak : moov.children) {
        Cipher c = trak_ciphers.get(trak.offset);
        if (c != null) {
          deDrmTransforms(trak, c, r, transforms);
        }
      }
      
      // Apply the transforms to generate a new file
      transformFile(f, g, transforms);
    }
    r.close();
  }
  
  // Compute the name of the undrmed version of a file.
  private static File unDrmFile(File f) {
    String name = f.toString();
    if (name.endsWith(".m4v")) {
      name = name.substring(0, name.length() - 4) + ".mp4";
    } else {
      name = name.substring(0, name.length() - 4) + ".m4a";
    }
    return new File(name);
  }
  
  /** Removes the DRM from f, writes the result to g, and returns true.
      If no DRM is found, g is not written and it returns false. */
  public static boolean unDrm(File f, File g) throws Exception {
    Map<Long,Cipher> ciphers = getCiphers(f, null /* TODO */);
    if (ciphers == null || ciphers.size() == 0) return false;
    unDrm(f, g, ciphers);
    return true;
  }
  
  /** Removes the DRM from f, writes the result to a new file, and returns that file.
      If no DRM is found, returns null. */
  public static File unDrm(File f) throws Exception {
    File g = unDrmFile(f);
    if (unDrm(f, g)) return g;
    return null;
  }
  
  public static void main(String[] args) throws Exception {
    if (args.length == 1) {
      unDrm(new File(args[0]));
    } else {
      unDrm(new File(args[0]), new File(args[1]));
    }
  }
}
