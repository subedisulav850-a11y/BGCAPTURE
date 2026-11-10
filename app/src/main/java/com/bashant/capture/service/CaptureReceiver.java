package com.bashant.capture.service;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import com.bashant.capture.proxy.CapturedPacket;
import com.bashant.capture.proxy.PacketStore;
import com.bashant.capture.utils.ExportUtils;

public class CaptureReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context ctx, Intent intent) {
        if (intent == null) return;
        switch (String.valueOf(intent.getAction())) {
            case "com.bashant.capture.ACTION_STOP":
                Intent stop = new Intent(ctx, BashantVpnService.class)
                        .setAction(BashantVpnService.ACTION_STOP);
                ctx.startService(stop);
                break;
            case "com.bashant.capture.ACTION_LAUNCH_FF":
                FreeFireLauncher.launch(ctx);
                break;
            case "com.bashant.capture.ACTION_EXPORT":
                ExportUtils.exportToDownloads(ctx, PacketStore.get().snapshot());
                break;
        }
    }
}
