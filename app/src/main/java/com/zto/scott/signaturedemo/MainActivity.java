package com.zto.scott.signaturedemo;

import android.annotation.SuppressLint;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import com.zto.encrypt.DataLock;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        Button btn = findViewById(R.id.btn_str);
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String str = new DataLock().stringFromJNI();
                Toast.makeText(getApplicationContext(), "JNI参数：" + str, Toast.LENGTH_SHORT).show();

            }
        });

        Button btn01 = findViewById(R.id.btn_signature);
        btn01.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String str = new DataLock().getSignatureStr("我很好");
                Toast.makeText(getApplicationContext(), "So签名参数：" + str, Toast.LENGTH_SHORT).show();
            }
        });

        Button btn02 = findViewById(R.id.btn_java_signature);
        btn02.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //String str = getSignStr(getApplicationContext());
                String str = getSing();
                Toast.makeText(getApplicationContext(), "JAVA签名参数：" + str, Toast.LENGTH_SHORT).show();
            }
        });

    }


    public String getSing(){
        try {
            @SuppressLint("PackageManagerGetSignatures")
            PackageInfo packageInfo = getApplicationContext().getPackageManager().getPackageInfo(getApplicationContext().getPackageName(), PackageManager.GET_SIGNATURES);
           return PackageUtils.getInstance().getSignatureDigest(packageInfo);

        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return "";
    }



    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
