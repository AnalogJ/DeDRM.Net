using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DeDRM.Library.Amazon.Mobi
{
    public class MobiHeader{
        public static  int HEADER_SIZE = 78;
        public static  String TEXT_READ = "TEXtREAd";
        public static  String BOOK_MOBI = "BOOKMOBI";
        private String mMagic;
        private int mNumSections;

        public MobiHeader(ArraySlice headerSlice){
            mMagic = System.Text.Encoding.Default.GetString(headerSlice.byteSlice(0x3C, 8));
            if(!mMagic.Equals(BOOK_MOBI) && !mMagic.Equals(TEXT_READ))
                throw new Exception("Invalid File Format");

            mNumSections = headerSlice.getShort(76);
        }

        public String toString(){
            return "Magic: " + mMagic + "\nNumber of Sections: " + mNumSections;
        }

        public String getMagicString(){return mMagic;}
        public int getNumberSections(){return mNumSections;}
    }

}
