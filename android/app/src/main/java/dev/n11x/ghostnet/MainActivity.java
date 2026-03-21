package dev.n11x.ghostnet;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;
import com.getcapacitor.SplashScreen;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        // Must be called before super.onCreate for modern Capacitor, 
        // but user requested "after super.onCreate()", let's follow the user.
        super.onCreate(savedInstanceState);
        SplashScreen.show(this);
    }
}
