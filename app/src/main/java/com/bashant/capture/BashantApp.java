package com.bashant.capture;

import android.app.Application;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.os.Build;
import androidx.multidex.MultiDex;
import android.content.Context;

public class BashantApp extends Application {

    public static final String CHANNEL_ID_CAPTURE  = "bashant_capture";
    public static final String CHANNEL_ID_OVERLAY  = "bashant_overlay";

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        MultiDex.install(this);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannels();
    }

    private void createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = getSystemService(NotificationManager.class);

            NotificationChannel cap = new NotificationChannel(
                    CHANNEL_ID_CAPTURE,
                    "Packet Capture",
                    NotificationManager.IMPORTANCE_LOW);
            cap.setDescription("BASHANT CAPTURE — VPN packet interception");
            cap.setShowBadge(false);

            NotificationChannel ov = new NotificationChannel(
                    CHANNEL_ID_OVERLAY,
                    "Log Overlay",
                    NotificationManager.IMPORTANCE_LOW);
            ov.setDescription("Floating log window");

            nm.createNotificationChannel(cap);
            nm.createNotificationChannel(ov);
        }
    }
}
