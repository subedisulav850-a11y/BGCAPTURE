package com.bashant.capture.service;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.widget.Toast;

public class FreeFireLauncher {

    private static final String[] FF_PACKAGES = {
        "com.dts.freefiremax",
        "com.dts.freefireth",
        "com.garena.game.fflite",
        "com.garena.game.ff",
    };

    public static boolean isInstalled(Context ctx) {
        PackageManager pm = ctx.getPackageManager();
        for (String pkg : FF_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {}
        }
        return false;
    }

    public static String installedPackage(Context ctx) {
        PackageManager pm = ctx.getPackageManager();
        for (String pkg : FF_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0);
                return pkg;
            } catch (PackageManager.NameNotFoundException ignored) {}
        }
        return null;
    }

    public static void launch(Context ctx) {
        String pkg = installedPackage(ctx);
        if (pkg == null) {
            Toast.makeText(ctx, "Free Fire not installed", Toast.LENGTH_SHORT).show();
            return;
        }
        PackageManager pm = ctx.getPackageManager();
        Intent launchIntent = pm.getLaunchIntentForPackage(pkg);
        if (launchIntent != null) {
            launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            ctx.startActivity(launchIntent);
        } else {
            Toast.makeText(ctx, "Cannot launch " + pkg, Toast.LENGTH_SHORT).show();
        }
    }
}
