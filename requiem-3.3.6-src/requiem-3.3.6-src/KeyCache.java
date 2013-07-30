import java.util.*;
import java.util.logging.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

class KeyCache {
  private static final Logger log = Logger.getLogger(KeyCache.class.getName());
  
  static class KeyData {
    SecretKeySpec key;
    boolean verified;
    char kind;
    KeyData(SecretKeySpec key, boolean verified, char kind) {
      this.key = key;
      this.verified = verified;
      this.kind = kind;
    }
  }
  
  static class UserKey {
    int userId;
    int keyId;
    UserKey(int userId, int keyId) {
      this.userId = userId;
      this.keyId = keyId;
    }
    public boolean equals(Object o) {
      if (!(o instanceof UserKey)) return false;
      UserKey x = (UserKey)o;
      return x.userId == userId && x.keyId == keyId;
    }
    public int hashCode() {
      return (userId << 8) + keyId;
    }
  }
  private static HashMap<UserKey,List<KeyData>> keys = null;
  
  private static boolean useKeyCache = true;
  private static String keyCache = Config.keyStore();

  private static HashSet<UserKey> undecodable_keys = new HashSet<UserKey>();
  static boolean isUndecodableKey(int user_id, int key_id) {
    return undecodable_keys.contains(new UserKey(user_id, key_id));
  }
  
  static {
    String p = System.getProperty("requiem.useKeyCache");
    if (p != null) useKeyCache = p.equals("1");
    p = System.getProperty("requiem.keyCache");
    if (p != null) keyCache = p;
  }
  
  private static void read() {
    assert keys == null;
    keys = new HashMap<UserKey,List<KeyData>>();
    if (!useKeyCache) return;
    try {
      BufferedReader r = new BufferedReader(new FileReader(keyCache));
      String version = r.readLine();
      if (!version.startsWith("version ")) { // old-style versionless cache
        version = "version 1";
        r.close();
        r = new BufferedReader(new FileReader(keyCache)); // restart reader
      }
      if (!version.equals("version 1")) return; // ignore other versions - print warning?
      while (true) {
        String line = r.readLine();
        if (line == null) break;
        String[] parts = line.split(" ");
        if (parts.length != 5) continue;
        int userId = (int)Long.parseLong(parts[0], 16);
        int keyId = (int)Long.parseLong(parts[1], 16);
        if (parts[2].length() != 32) continue;
        byte[] keyBytes = new byte[16];
        for (int i = 0; i < 16; i++) {
          keyBytes[i] = (byte)Integer.parseInt(parts[2].substring(2 * i, 2 * i + 2), 16);
        }
        boolean verified = parts[3].equals("1");
        char kind = parts[4].charAt(0);
        
        UserKey userKey = new UserKey(userId, keyId);
        if (!keys.containsKey(userKey)) keys.put(userKey, new ArrayList<KeyData>());
        keys.get(userKey).add(new KeyData(new SecretKeySpec(keyBytes, "AES"), verified, kind));
      }
    } catch (IOException e) {
      // will happen, for example, when no requiem-keystore exists
    }
  }
  
  private static String displayStr(SecretKeySpec key) {
    String s = "";
    for (int i = 0; i < 16; i++) {
      s += String.format("%02x", key.getEncoded()[i] & 0xff);
    }
    return s;
  }
  
  private static void write() throws IOException {
    if (!useKeyCache) return;
    PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(keyCache)));
    w.println("version 1");
    for (UserKey k : keys.keySet()) {
      for (KeyData d : keys.get(k)) {
        w.print(Integer.toHexString(k.userId));
        w.print(" ");
        w.print(Integer.toHexString(k.keyId));
        w.print(" ");
        w.print(displayStr(d.key));
        w.print(" ");
        w.print(d.verified ? "1" : "0");
        w.print(" ");
        w.println(d.kind);
      }
    }
    w.close();
  }
  
  public static List<SecretKeySpec> getKey(int userId, int keyId) {
    // allocate return list
    List<SecretKeySpec> list = new ArrayList<SecretKeySpec>();
    if (userId == 0 && keyId == 0) { // special global key
      list.add(new SecretKeySpec("tr1-th3n.y00_by3".getBytes(), "AES"));
      return list;
    }
    
    if (keys == null) read();
    List<KeyData> keydata = keys.get(new UserKey(userId, keyId));
    if (keydata != null) {
      for (KeyData k : keydata) {
        list.add(k.key);
      }
    }
    return list;
  }
  
  public static void addKey(int userId, int keyId, byte[] key, char kind) throws IOException {
    addKey(userId, keyId, new SecretKeySpec(key, "AES"), kind);
  }
  public static void addKey(int userId, int keyId, SecretKeySpec key, char kind) throws IOException {
    if (keys == null) {
      keys = new HashMap<UserKey,List<KeyData>>();
      useKeyCache = false; // make sure we don't write back partial data
    }
    UserKey k = new UserKey(userId, keyId);
    if (!keys.containsKey(k)) keys.put(k, new ArrayList<KeyData>());
    for (KeyData d : keys.get(k)) {
      if (key.equals(d.key)) { // already have it
        log.info("Matching key " + Integer.toHexString(userId) + "/" + Integer.toHexString(keyId) + " " + displayStr(key));
        return;
      }
    }
    log.info("Adding key " + Integer.toHexString(userId) + "/" + Integer.toHexString(keyId) + " " + displayStr(key));
    keys.get(k).add(new KeyData(key, false, kind));
    write();
  }
  public static void noKey(int userId, int keyId) {
    log.info("no key " + Integer.toHexString(userId) + "/" + Integer.toHexString(keyId));
    undecodable_keys.add(new UserKey(userId, keyId));
  }
  
  public static void verifyKey(int userId, int keyId, SecretKeySpec key) throws IOException {
    if (userId == 0 && keyId == 0) return;
    List<KeyData> keydata = keys.get(new UserKey(userId, keyId));
    assert keydata != null;
    for (KeyData k : keydata) {
      if (k.key.equals(key)) {
        keydata.clear();
        keydata.add(k);
        if (!k.verified) {
          k.verified = true;
          write();
        }
        return;
      }
    }
    assert false; // will only verify a key we have
  }
  public static void badKey(int userId, int keyId, SecretKeySpec key) throws IOException {
    log.warning("bad key " + Integer.toHexString(userId) + "/" + Integer.toHexString(keyId) + " " + displayStr(key));
  }
}
