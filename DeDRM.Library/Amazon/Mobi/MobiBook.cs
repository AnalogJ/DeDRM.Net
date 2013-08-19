using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DeDRM.Library.Amazon.Mobi
{
    //TODO: place IRemoveDrm Interface. 
    public class MobiBook {

    private ArraySlice mEncMobiBook;
    private MobiHeader mHeader = null;
    private List<Section> mSections = new List<Section>();
    private Dictionary<Int32, byte[]> mMetaMap = new Dictionary<Int32,byte[]>();
    private int mMobiLength { get; set; }
    private int mMobiCodepage { get; set; }
    private int mMobiVersion { get; set; }
    private int mCompression { get; set; }
    private int mRecords { get; set; }
    private int mExtraDataFlags = 0;
    private Boolean mPrintReplica = false;

    public MobiBook(String filename){
       mEncMobiBook = getBookSlice(filename);
       mHeader = new MobiHeader(mEncMobiBook);
       mEncMobiBook.seek(MobiHeader.HEADER_SIZE);

       for(int i = 0; i < mHeader.getNumberSections(); i++)
            mSections.Add(new Section(mEncMobiBook));

       int offset =  (int)mSections[0].offset;

       mCompression = mEncMobiBook.getShort(offset);
       mRecords = mEncMobiBook.getShort(offset + 0x8);

       if(mHeader.getMagicString().Equals(MobiHeader.TEXT_READ)){
           mExtraDataFlags = 0;
           mMobiLength = 0;
           mMobiCodepage = 0;
           mMobiVersion = -1;
           return;
       }

       mMobiLength = (int)mEncMobiBook.getLong(offset + 0x14);
       mMobiCodepage = (int)mEncMobiBook.getLong(offset + 0x1c);
       mMobiVersion = (int)mEncMobiBook.getLong(offset + 0x68);

       if ((mMobiLength >= 0xE4) && (mMobiVersion >= 5)){
         mExtraDataFlags = mEncMobiBook.getShort(offset + 0xF2);
       }

       if(mCompression != 17480){
           // multibyte utf8 data is included in the encryption for PalmDoc compression
           // so clear that byte so that we leave it to be decrypted.
           mExtraDataFlags &= 0xFFFE;
       }


       //if exth region exists parse it for metadata array
       int exthFlag =  (int)mEncMobiBook.getLong(offset + 0x80);
       int exthOffset = 16 + mMobiLength;
       if((exthFlag & 0x40) > 0) {
           if((exthOffset + mEncMobiBook.size() >= 4) && System.Text.Encoding.Default.GetString(mEncMobiBook.byteSlice(exthOffset+offset,4)).Equals("EXTH")){
              int nItems =(int) mEncMobiBook.getLong(exthOffset + offset + 8);
              int pos = offset + exthOffset + 12;
              for(int i = 0; i < nItems-1; i++){
                  int type = (int)mEncMobiBook.getLong(pos);
                  int size = (int)mEncMobiBook.getLong(pos + 4);
                  mMetaMap[type] = mEncMobiBook.byteSlice(pos+8, size-8);
                  /* TODO:
                     # reset the text to speech flag and clipping limit, if present
                    if type == 401 and size == 9:
                        # set clipping limit to 100%
                        self.patchSection(0, "\144", 16 + self.mobi_length + pos + 8)
                    elif type == 404 and size == 9:
                        # make sure text to speech is enabled
                        self.patchSection(0, "\0", 16 + self.mobi_length + pos + 8)
                   */
                  pos += size;
              }
           }
       }

       Debug.WriteLine(mHeader);
       Debug.WriteLine("BookTitle: {0} \nMobiLength: {1} \nMobiCodePage {2}\nExtraDataFlags: {3} \nMobiVersion: {4}\n",getBookTitle(), mMobiLength, mMobiCodepage,mExtraDataFlags,mMobiVersion);
       List<byte[]> pidList = new List<byte[]>();
        pidList.Add(Encoding.Default.GetBytes("DL3pB54YXE"));
        pidList.Add(Encoding.Default.GetBytes("DL3pB54Y"));
        pidList.Add(Encoding.Default.GetBytes("SSEVC1U7"));
        processBook(pidList);
    }

    public String getBookTitle(){
        Dictionary<Int32, Encoding> codecMap = new Dictionary<Int32, Encoding>();
        codecMap[1252] = Encoding.GetEncoding(1252);
        codecMap[65001] = Encoding.UTF8;
        String title = null;
        if(mHeader.getMagicString().Equals(MobiHeader.BOOK_MOBI))
            if(mMetaMap.ContainsKey(503)){
                title = Encoding.Default.GetString(mMetaMap[503]);
            }else{
                int o = (int) mSections[0].offset;
                int toff = (int)mEncMobiBook.getLong(o + 0x54);
                int tsize = (int)mEncMobiBook.getLong();
                title = codecMap[mMobiCodepage].GetString(mEncMobiBook.byteSlice(toff + o, tsize));
            }
        if(title == null)
            title = Encoding.Default.GetString(mEncMobiBook.byteSlice(0,32)).Split('\0')[0];

        return title;
    }

    public void processBook(List<byte[]> pidList){
       int firstOffset = (int) mSections.ElementAt(0).offset;
       int cryptoType = mEncMobiBook.getShort(firstOffset+0xC);
       if(cryptoType == 0){
           Debug.WriteLine("This Book is not encrypted");
       }else if(cryptoType != 1 && cryptoType != 2)
           throw new Exception("Unknown Mobipocket CryptoType: " + cryptoType);

       if(mMetaMap.ContainsKey(406))
       {
           byte[] data406 = mMetaMap[406];
           if((new ArraySlice(data406)).getLongLong() != 0)
               throw new Exception("Cannot Decode library or rented eBooks");
       }

        List<byte[]> goodPids = validatePins(pidList);

        byte[] pid = {0,0,0,0,0,0,0,0};
        byte[] foundKey;
        if(cryptoType == 1){
            byte[] t1KeyVec = Encoding.Default.GetBytes("QDCVEPMU675RUBSZ");
            byte [] bookKeyData;

            if(mHeader.getMagicString().Equals(MobiHeader.TEXT_READ))
                bookKeyData = mEncMobiBook.byteSlice(0x0E + firstOffset, 16);
            else if(mMobiVersion <0)
                bookKeyData = mEncMobiBook.byteSlice(0x90 + firstOffset, 16);
            else
                bookKeyData = mEncMobiBook.byteSlice(mMobiLength + firstOffset + 16, 16);

            foundKey = PK1Dec(bookKeyData,t1KeyVec,false);
        }else{
            int drmPointer = (int)mEncMobiBook.getLong(firstOffset + 0xA8);
            int drmCount =  (int)mEncMobiBook.getLong();
            int drmSize = (int)mEncMobiBook.getLong();
            int drmFlags = (int)mEncMobiBook.getLong();
            parseDRM(mEncMobiBook.byteSlice(drmPointer+firstOffset, drmSize),drmCount,goodPids);
        }
    }
    public void parseDRM(byte[] byteData, int drmCount, List<byte[]>pidList) {
         byte[] keyVec1 = new byte[] {0x72,0x38,0x33,(byte)0xB0,(byte)0xB4,(byte)0xF2,(byte)0xE3,(byte)0xCA,(byte)0xDF,0x09,0x01,(byte)0xD6,(byte)0xE2,(byte)0xE0,0x3F,(byte)0x96};
         foreach(byte[] pid in pidList){
           byte[] bigpid = new byte[16];
             for(int i = 0; i < 16; i++)
                 bigpid[i] = 0x00;

             for(int i =0; i < pid.Count(); i++)
                 bigpid[i] = pid[i];
                byte[] tempKey = PK1Enc(bigpid,keyVec1);
             int tempKeySum = 0;
             for(int i=0; i < tempKey.Count(); i++)
            	 tempKeySum+= tempKey[i];
             tempKeySum = tempKeySum & 0xFF;
             ArraySlice data = new ArraySlice(byteData);
             for(int i=0; i < drmCount; i++){
            	 int verification = (int) data.getLong(i * 0x30);
            	 int size 		  = (int) data.getLong(i * 0x30 + 4);
            	 int type		  = (int) data.getLong(i * 0x30 + 8);
            	 int chkSum		  = (int) data.getByte(i * 0x30 + 12) & 0xFF;
            	 byte[] cookie    =  	  data.byteSlice(i * 0x30 + 16, 32);

            	 if(chkSum == tempKeySum){
            		 Debug.WriteLine("Cookie: "  + bytesToHex(cookie) + " Found at DRMCount: " + i);
            		 Debug.WriteLine("Temp Key: " + bytesToHex(tempKey));
            		 cookie = PK1Dec(cookie, tempKey,true);
            		 Debug.WriteLine("Decrypted Cookie: "  + bytesToHex(cookie) + " Found at DRMCount: " + i);
            		 ArraySlice slice = new ArraySlice(cookie);
            		 int ver = (int) slice.getLong();
            		 int flags = (int) slice.getLong();
            		 int finalkey = (int) slice.getLong();
            		 if(verification == ver && ((flags & 0x1F) > 0)){
            			 Debug.WriteLine("W00000T");
            		 }
            	 }
             }
             
             Debug.WriteLine("PID: " + Encoding.Default.GetString(pid));
             Debug.WriteLine("HEX BIGPID: " +  bytesToHex(bigpid));
             Debug.WriteLine("Key Vec:    " +  bytesToHex(keyVec1));
             Debug.WriteLine("Temp Key:   " +  bytesToHex(tempKey));
             Debug.WriteLine("Dec Key:    " +  bytesToHex(PK1Dec(tempKey,keyVec1,false)));
             Debug.WriteLine("\n\n");
         }
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        Int32 count = bytes.Count();
        char[] hexChars = new char[count * 2];
        int v; //TODO: this was an unsigned int previously. 
        for ( int j = 0; j < bytes.Count(); j++ ) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


    private byte[] PK1Enc(byte[] data, byte[] key){
    	return PK(data,key,false,false);
    }
    private byte[] PK1Dec(byte[] data, byte[] key,Boolean debug){
    	return PK(data,key,true,debug);
    } 
    private byte[] PK(byte[]data, byte[] key, Boolean dec,Boolean debug){
        MemoryStream plainTextStream = new MemoryStream();
    	int sum1=0,sum2=0,keyXorVal=0;
    	byte curByte;
    	int[] wkey = new int[8];
    	for(int i=0; i < 8; i++)
    		wkey[i] = (key[i*2] << 8 & 0xFF00) | (key[i*2 +1] & 0xFF) ;
    	for(int i=0; i < data.Count(); i++){
           // debug = i == 8;
    		curByte = data[i];
            if(debug)
            Debug.WriteLine("Working on byte: " + i);

    		int temp = 0, byteXorVal=0;
    		for(int j=0; j<8; j++){
    			temp ^= wkey[j];
                sum2  = (sum2+j)*20021 + sum1;
                sum1  = (temp*346)     & 0xFFFF;
                sum2  = (sum2+sum1)    & 0xFFFF;
                temp =  (temp*20021+1) & 0xFFFF;
                byteXorVal ^= temp ^ sum2;
    		}
            if(debug)      {
                Debug.WriteLine("ByteX0rVal: "  + byteXorVal.ToString("X"));
                String www = "";
                foreach(int kk in wkey)
                {
                    String s = (kk & 0xFFFF).ToString("X");
                    for(int iiii = 0; iiii < s.Count() % 4; iiii ++ )
                        www += "0";
                    www += s;
                }

                Debug.WriteLine("hkey: " + www);
                Debug.WriteLine("temp: "  + temp.ToString("X"));
                Debug.WriteLine("sum1: "  + sum1.ToString("X"));
                Debug.WriteLine("sum2: "  + sum2.ToString("X"));
                Debug.WriteLine("keyX0rVal: "  + keyXorVal.ToString("X"));
            }

    		if(!dec)
    			keyXorVal = (curByte * 257);
    		curByte = (byte) (((curByte ^ (byteXorVal >> 8)) ^ byteXorVal) & 0xFF);
    		if(dec)
    			keyXorVal = (curByte * 257) * 0xFFFF;

            if(false){
                Debug.WriteLine("--------------------------------------------");
                Debug.WriteLine("keyX0rVal1: " + keyXorVal.ToString("X"));
                Debug.WriteLine("--------------------------------------------");
            }
    		for(int j =0; j <8; j++)
    			wkey[j] ^= (keyXorVal & 0xFFFF);

            plainTextStream.WriteByte(curByte);
            if(debug)      {
                Debug.WriteLine("--------------------------------------------");
                Debug.WriteLine("ByteX0rVal: " + byteXorVal.ToString("X"));
                String www = "";
                foreach(int kk in wkey)
                {
                    String s = (kk & 0xFFFF).ToString("X");
                    for(int iiii = 0; iiii < s.Count() % 4; iiii ++ )
                        www += "0";
                    www += s;
                }

                Debug.WriteLine("hkey: " + www);
                Debug.WriteLine("temp: "  + temp.ToString("X"));
                Debug.WriteLine("sum1: " + sum1.ToString("X"));
                Debug.WriteLine("sum2: " + sum2.ToString("X"));
                Debug.WriteLine("keyX0rVal: " + keyXorVal.ToString("X"));
                Debug.WriteLine("--------------------------------------------");
            }

        }
    	return plainTextStream.ToArray();
    }
 
    private List<byte[]> validatePins(List<byte[]> pids){
        List<byte[]> vPids = new List<byte[]>();
            foreach(byte[] s in pids)
              vPids.Add(validatePid(s));
                 return vPids;
    }
    
    private byte[] validatePid(byte[] pid){
        return pid;
    }
    

    
    ArraySlice getBookSlice(String filename)
    {
        FileStream fs = File.OpenRead(filename);

        byte[] file = new byte[(int)fs.Length];
        fs.Read(file, 0, file.Length);

        return new ArraySlice(file);
    }
}

}
