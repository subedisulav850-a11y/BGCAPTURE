package com.bashant.capture.service;

import android.app.*;
import android.content.Intent;
import android.graphics.*;
import android.os.Build;
import android.os.IBinder;
import android.view.*;
import android.widget.*;
import androidx.core.app.NotificationCompat;

import com.bashant.capture.BashantApp;
import com.bashant.capture.R;
import com.bashant.capture.proxy.CapturedPacket;
import com.bashant.capture.proxy.PacketStore;
import com.bashant.capture.ui.MainActivity;

import java.util.LinkedList;

/**
 * Floating overlay window that shows live capture logs on top of Free Fire.
 * Respects the user toggle — only active when EXTRA_SHOW_OVERLAY=true.
 */
public class OverlayService extends Service implements PacketStore.Listener {

    private static final int NOTIF_ID = 1002;
    private static final int MAX_LINES = 20;

    private WindowManager   wm;
    private View            overlayView;
    private TextView        logTextView;
    private final LinkedList<String> lines = new LinkedList<>();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIF_ID, buildNotification());
        showOverlay();
        PacketStore.get().addListener(this);
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        PacketStore.get().removeListener(this);
        hideOverlay();
        stopForeground(true);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }

    // ── Overlay window ────────────────────────────────────────────────────

    private void showOverlay() {
        wm = (WindowManager) getSystemService(WINDOW_SERVICE);

        // Root layout
        overlayView = new FrameLayout(this);
        overlayView.setBackgroundColor(Color.argb(180, 0, 0, 0));
        overlayView.setPadding(12, 8, 12, 8);

        LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);

        // Title bar
        LinearLayout titleBar = new LinearLayout(this);
        titleBar.setOrientation(LinearLayout.HORIZONTAL);
        titleBar.setGravity(Gravity.CENTER_VERTICAL);

        TextView title = new TextView(this);
        title.setText("⚡ BASHANT CAPTURE");
        title.setTextColor(Color.parseColor("#4ADE80"));
        title.setTextSize(10f);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setLayoutParams(new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button closeBtn = new Button(this);
        closeBtn.setText("✕");
        closeBtn.setTextSize(9f);
        closeBtn.setTextColor(Color.RED);
        closeBtn.setBackgroundColor(Color.TRANSPARENT);
        closeBtn.setPadding(4, 0, 4, 0);
        LinearLayout.LayoutParams closeLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        closeBtn.setLayoutParams(closeLp);
        closeBtn.setOnClickListener(v -> stopSelf());

        titleBar.addView(title);
        titleBar.addView(closeBtn);

        // Log area
        logTextView = new TextView(this);
        logTextView.setTextColor(Color.parseColor("#E6EDF3"));
        logTextView.setTextSize(8.5f);
        logTextView.setTypeface(Typeface.MONOSPACE);
        logTextView.setMaxLines(MAX_LINES);
        logTextView.setText("Waiting for packets…");

        container.addView(titleBar);
        container.addView(logTextView);
        ((FrameLayout) overlayView).addView(container);

        // Window params
        int overlayType = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                : WindowManager.LayoutParams.TYPE_PHONE;

        WindowManager.LayoutParams params = new WindowManager.LayoutParams(
                (int)(getResources().getDisplayMetrics().widthPixels * 0.65f),
                WindowManager.LayoutParams.WRAP_CONTENT,
                overlayType,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                        | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL
                        | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                PixelFormat.TRANSLUCENT);
        params.gravity = Gravity.TOP | Gravity.START;
        params.x = 10;
        params.y = 60;

        // Drag to move
        overlayView.setOnTouchListener(new MoveTouchListener(wm, params, overlayView));

        wm.addView(overlayView, params);
    }

    private void hideOverlay() {
        if (wm != null && overlayView != null) {
            try { wm.removeView(overlayView); } catch (Exception ignored) {}
            overlayView = null;
        }
    }

    // ── PacketStore.Listener ──────────────────────────────────────────────

    @Override
    public void onPacketAdded(CapturedPacket pkt) {
        String line = String.format("%s %s %s %dB [%s]",
                pkt.getTimestampStr(),
                pkt.protocol.name(),
                pkt.direction == CapturedPacket.Direction.CLIENT_TO_SERVER ? "▲" : "▼",
                pkt.rawData != null ? pkt.rawData.length : 0,
                pkt.label != null ? pkt.label : "");
        lines.addFirst(line);
        if (lines.size() > MAX_LINES) lines.removeLast();

        final String text = String.join("\n", lines);
        if (logTextView != null) {
            logTextView.post(() -> logTextView.setText(text));
        }
    }

    // ── Notification ──────────────────────────────────────────────────────

    private Notification buildNotification() {
        Intent mainIntent = new Intent(this, MainActivity.class);
        PendingIntent mainPi = PendingIntent.getActivity(this, 0, mainIntent,
                PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, BashantApp.CHANNEL_ID_OVERLAY)
                .setContentTitle("BASHANT — Overlay Active")
                .setContentText("Log window is on screen")
                .setSmallIcon(R.drawable.ic_capture)
                .setContentIntent(mainPi)
                .setOngoing(true)
                .build();
    }

    // ── Drag touch listener ───────────────────────────────────────────────

    private static class MoveTouchListener implements View.OnTouchListener {
        private final WindowManager wm;
        private final WindowManager.LayoutParams params;
        private final View view;
        private float startX, startY, initX, initY;

        MoveTouchListener(WindowManager wm, WindowManager.LayoutParams params, View view) {
            this.wm = wm; this.params = params; this.view = view;
        }

        @Override
        public boolean onTouch(View v, MotionEvent e) {
            switch (e.getAction()) {
                case MotionEvent.ACTION_DOWN:
                    startX = e.getRawX(); startY = e.getRawY();
                    initX = params.x;    initY  = params.y;
                    return true;
                case MotionEvent.ACTION_MOVE:
                    params.x = (int)(initX + e.getRawX() - startX);
                    params.y = (int)(initY + e.getRawY() - startY);
                    wm.updateViewLayout(view, params);
                    return true;
            }
            return false;
        }
    }
}
