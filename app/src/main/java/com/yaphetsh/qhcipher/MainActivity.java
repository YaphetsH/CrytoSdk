package com.yaphetsh.qhcipher;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.util.Arrays;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
//    static {
//        System.loadLibrary("native-lib");
//    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        String version = NativeHelper.hellpCipher();
        tv.setText(version);

        String test_gps_str = "02681a001838d20c89e6b04c57fe1493f1269f81cc0d59ba496b";
        byte[] bytes = hexStringToByteArray(test_gps_str);

        //byte[] data =  Arrays.copyOfRange(crytp,4,crytp.length);

         byte[] crytp = NativeHelper.encryptBuffer(bytes,0x1a);
        //byte[] data =  Arrays.copyOfRange(crytp,4,crytp.length);
      //  Log.d("yaphetshan", Arrays.toString(bytes));

      //  byte[] ori = NativeHelper.decryptBuffer(data,crytp.length-4);
//        Log.d("yaphetshan", Arrays.toString(bytes));
        Log.d("yaphetshan", Arrays.toString(bytes));

        Log.d("yaphetshan", Arrays.toString(crytp));
       // Log.d("yaphetshan", Arrays.toString(data));

      //  Log.d("yaphetshan", Arrays.toString(decrypt));

        // Log.d("yaphetshan", Arrays.toString(ori));

      //   byte[] test_sps_str = new byte[1395];

      //  Log.d("yaphetshan", NativeHelper.getPackSize(bytes,0)+"");

    }
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    //public native String stringFromJNI();
}
