package com.zto.encrypt;

/**
 * Created by Scott on 2018/5/22.
 */

public class DataLock {
    static {
        // load library
        try {
            System.loadLibrary("zto-signature");
        } catch (UnsatisfiedLinkError ule) {
            System.err.println("WARNING: Could not load library!");
        }
    }


    /**
     * native-lib中的原生方法
     */
    public native String stringFromJNI();


    public native String getSignatureStr(String signature);
}
