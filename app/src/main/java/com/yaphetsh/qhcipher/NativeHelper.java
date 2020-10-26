package com.yaphetsh.qhcipher;

public class NativeHelper {

    static {
        System.loadLibrary("QHCipher");
    }
    public static native String hellpCipher();


    public static  native  byte[] encryptBuffer(byte[] data,int size);
    public static  native  byte[] decryptBuffer(byte[] data,int size);
    public static  native  int getPackSize(byte[] data,int start);

    public static  native  int setPackInfo(byte[] data,int dataSize,int main,int sub);

    public static  native  int getCipherMode();


}
