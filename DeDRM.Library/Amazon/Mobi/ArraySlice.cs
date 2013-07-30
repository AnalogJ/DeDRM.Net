using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DeDRM.Library.Amazon.Mobi
{
    public class ArraySlice {
    byte[] mArray;
    int mOffset;

    public ArraySlice(byte[] arr){
        mArray = arr;
        mOffset = 0;
    }

    public ArraySlice(byte[] arr, int offset){
        mArray = arr;
        mOffset = offset;
    }

    public void seek(int offset){
        mOffset = offset;
    }

    public int size(){ return mArray.Count();}

    public byte[] byteSlice(int offset, int size){
        byte[] destination = new byte[size];
        Buffer.BlockCopy(mArray, offset, destination, 0, size);
        return destination;
    }

    public int getShort(){
        int i = ((mArray[mOffset] & 0xFF) << 8) | (mArray[mOffset+1] & 0xFF);
        mOffset += 2;
        return i;
    }

    public long getLongLong(){
        return
                ((mArray[mOffset] & 0xFF) << 56)     |
                ((mArray[mOffset+1] & 0xFF) << 48)   |
                ((mArray[mOffset+2] & 0xFF) << 40)   |
                ((mArray[mOffset+3] & 0xFF) << 32)   |
                ((mArray[mOffset+4] & 0xFF) << 24)   |
                ((mArray[mOffset+5] & 0xFF) << 16)   |
                ((mArray[mOffset+6] & 0xFF) << 8)    |
                (mArray[mOffset+7] & 0xFF);
    }

    public long getLongLong(int offSet){
        mOffset = offSet;
        return getLong();
    }

    public byte getByte(){
        byte b = mArray[mOffset];
        mOffset+=1;
        return b;
    }

    public long getLong(){
       long l = ((mArray[mOffset] & 0xFF) << 24) | ((mArray[mOffset+1] & 0xFF) << 16) | ((mArray[mOffset+2] & 0xFF) << 8) | (mArray[mOffset+3] & 0xFF);
       mOffset += 4;
       return l;
    }

    public long getLong(int offset){
        mOffset = offset;
        return getLong();
    }

    public int getShort(int offset){
        mOffset = offset;
        return getShort();
    }
    

	public int getByte(int offset) {
		mOffset = offset;
		return getByte();
	}

}
}
