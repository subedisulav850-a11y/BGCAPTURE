package com.bashant.capture.utils;

import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import android.widget.Toast;

import com.bashant.capture.proxy.CapturedPacket;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;

public class ExportUtils {

    public static void exportToDownloads(Context ctx, List<CapturedPacket> packets) {
        if (packets == null || packets.isEmpty()) {
            Toast.makeText(ctx, "No packets to export", Toast.LENGTH_SHORT).show();
            return;
        }
        String fname = "bashant_capture_"
                + new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date())
                + ".txt";
        String content = buildExportText(packets);
        try {
            writeToDownloads(ctx, fname, content);
            Toast.makeText(ctx, "Exported: " + fname, Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(ctx, "Export failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private static void writeToDownloads(Context ctx, String fname, String content)
            throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ContentValues cv = new ContentValues();
            cv.put(MediaStore.Downloads.DISPLAY_NAME, fname);
            cv.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
            cv.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
            Uri uri = ctx.getContentResolver()
                    .insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
            if (uri == null) throw new IOException("MediaStore insert returned null");
            try (OutputStream out = ctx.getContentResolver().openOutputStream(uri)) {
                if (out == null) throw new IOException("openOutputStream returned null");
                out.write(content.getBytes("UTF-8"));
            }
        } else {
            File dir = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS);
            if (!dir.exists()) dir.mkdirs();
            File f = new File(dir, fname);
            try (FileWriter fw = new FileWriter(f)) {
                fw.write(content);
            }
        }
    }

    private static String buildExportText(List<CapturedPacket> packets) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════\n");
        sb.append("     BASHANT CAPTURE INTERNAL APP — EXPORT\n");
        sb.append("     FULL CREDIT @Bgcodex\n");
        sb.append("     Exported: ")
          .append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date()))
          .append("\n");
        sb.append("     Total packets: ").append(packets.size()).append("\n");
        sb.append("═══════════════════════════════════════════════════\n\n");
        for (CapturedPacket pkt : packets) {
            sb.append(pkt.toDetailString()).append("\n");
        }
        return sb.toString();
    }
}
