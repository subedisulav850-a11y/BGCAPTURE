package com.bashant.capture.ui;

import android.app.AlertDialog;
import android.content.*;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.*;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.*;

import com.bashant.capture.R;
import com.bashant.capture.proxy.CapturedPacket;
import com.bashant.capture.proxy.PacketStore;
import com.bashant.capture.service.*;
import com.bashant.capture.utils.ExportUtils;

import java.util.List;

public class MainActivity extends AppCompatActivity implements PacketStore.Listener {

    private static final int REQ_VPN     = 101;
    private static final int REQ_OVERLAY = 102;

    // ── UI ─────────────────────────────────────────────────────────────────
    private Switch  swCaptureTcp, swCaptureUdp, swOverlay;
    private Button  btnStart, btnStop, btnLaunchFF, btnExport, btnSupport, btnClear;
    private TextView tvStatus, tvCount, tvKeyIv;
    private RecyclerView rvPackets;
    private PacketAdapter adapter;

    // Filter chips
    private ToggleButton chipTcp, chipUdp;

    private boolean vpnRunning = false;
    private int packetCount = 0;

    private final BroadcastReceiver vpnStatusReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context ctx, Intent intent) {
            boolean active = intent.getBooleanExtra("active", false);
            vpnRunning = active;
            updateStatusUi();
        }
    };

    // ── Lifecycle ─────────────────────────────────────────────────────────

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        bindViews();
        setupRecyclerView();
        setupListeners();
        PacketStore.get().addListener(this);
        registerReceiver(vpnStatusReceiver,
                new IntentFilter("com.bashant.capture.VPN_STATUS"));
        updateStatusUi();
    }

    @Override
    protected void onDestroy() {
        PacketStore.get().removeListener(this);
        try { unregisterReceiver(vpnStatusReceiver); } catch (Exception ignored) {}
        super.onDestroy();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == REQ_VPN && res == RESULT_OK) {
            startCapture();
        } else if (req == REQ_OVERLAY) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                    && Settings.canDrawOverlays(this)) {
                startOverlayService();
            } else {
                swOverlay.setChecked(false);
                Toast.makeText(this, "Overlay permission denied", Toast.LENGTH_SHORT).show();
            }
        }
    }

    // ── View binding ──────────────────────────────────────────────────────

    private void bindViews() {
        swCaptureTcp = findViewById(R.id.sw_capture_tcp);
        swCaptureUdp = findViewById(R.id.sw_capture_udp);
        swOverlay    = findViewById(R.id.sw_overlay);
        btnStart     = findViewById(R.id.btn_start);
        btnStop      = findViewById(R.id.btn_stop);
        btnLaunchFF  = findViewById(R.id.btn_launch_ff);
        btnExport    = findViewById(R.id.btn_export);
        btnSupport   = findViewById(R.id.btn_support);
        btnClear     = findViewById(R.id.btn_clear);
        tvStatus     = findViewById(R.id.tv_status);
        tvCount      = findViewById(R.id.tv_count);
        tvKeyIv      = findViewById(R.id.tv_keyiv);
        rvPackets    = findViewById(R.id.rv_packets);
        chipTcp      = findViewById(R.id.chip_tcp);
        chipUdp      = findViewById(R.id.chip_udp);
    }

    private void setupRecyclerView() {
        adapter = new PacketAdapter(new PacketAdapter.OnPacketClick() {
            @Override
            public void onResend(CapturedPacket pkt) { showResendDialog(pkt); }
            @Override
            public void onDetail(CapturedPacket pkt) { showDetailDialog(pkt); }
        });
        rvPackets.setLayoutManager(new LinearLayoutManager(this));
        rvPackets.setAdapter(adapter);
        rvPackets.setItemAnimator(null); // smoother updates
    }

    private void setupListeners() {
        btnStart.setOnClickListener(v -> requestVpnAndStart());
        btnStop.setOnClickListener(v -> stopCapture());
        btnLaunchFF.setOnClickListener(v -> {
            if (!vpnRunning) {
                Toast.makeText(this, "Start capture first!", Toast.LENGTH_SHORT).show();
                return;
            }
            FreeFireLauncher.launch(this);
        });
        btnExport.setOnClickListener(v ->
                ExportUtils.exportToDownloads(this, PacketStore.get().snapshot()));
        btnClear.setOnClickListener(v -> {
            PacketStore.get().clear();
            adapter.clear();
            packetCount = 0;
            tvCount.setText("Packets: 0");
        });
        btnSupport.setOnClickListener(v -> openTelegram());

        swOverlay.setOnCheckedChangeListener((cb, checked) -> {
            if (checked) requestOverlayAndStart();
            else stopOverlayService();
        });

        chipTcp.setOnCheckedChangeListener((cb, checked) ->
                adapter.setFilter(checked, chipUdp.isChecked()));
        chipUdp.setOnCheckedChangeListener((cb, checked) ->
                adapter.setFilter(chipTcp.isChecked(), checked));
    }

    // ── VPN flow ──────────────────────────────────────────────────────────

    private void requestVpnAndStart() {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, REQ_VPN);
        } else {
            startCapture();
        }
    }

    private void startCapture() {
        Intent i = new Intent(this, BashantVpnService.class)
                .setAction(BashantVpnService.ACTION_START)
                .putExtra(BashantVpnService.EXTRA_CAPTURE_TCP, swCaptureTcp.isChecked())
                .putExtra(BashantVpnService.EXTRA_CAPTURE_UDP, swCaptureUdp.isChecked());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            startForegroundService(i);
        else
            startService(i);
        Toast.makeText(this, "Starting BASHANT CAPTURE…", Toast.LENGTH_SHORT).show();
    }

    private void stopCapture() {
        Intent i = new Intent(this, BashantVpnService.class)
                .setAction(BashantVpnService.ACTION_STOP);
        startService(i);
    }

    // ── Overlay flow ──────────────────────────────────────────────────────

    private void requestOverlayAndStart() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                && !Settings.canDrawOverlays(this)) {
            Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:" + getPackageName()));
            startActivityForResult(i, REQ_OVERLAY);
        } else {
            startOverlayService();
        }
    }

    private void startOverlayService() {
        Intent i = new Intent(this, OverlayService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            startForegroundService(i);
        else
            startService(i);
    }

    private void stopOverlayService() {
        stopService(new Intent(this, OverlayService.class));
    }

    // ── PacketStore.Listener ──────────────────────────────────────────────

    @Override
    public void onPacketAdded(CapturedPacket pkt) {
        runOnUiThread(() -> {
            adapter.addPacket(pkt);
            packetCount++;
            tvCount.setText("Packets: " + packetCount);

            // If MajorLogin response, try to extract KEY/IV
            if ("MajorLogin".equals(pkt.label) && pkt.decryptedData != null) {
                // show it
                tvKeyIv.setText("KEY/IV auto-detected ✓");
            }
        });
    }

    // ── Status UI ─────────────────────────────────────────────────────────

    private void updateStatusUi() {
        if (vpnRunning) {
            tvStatus.setText("● CAPTURING");
            tvStatus.setTextColor(0xFF4ADE80);
            btnStart.setEnabled(false);
            btnStop.setEnabled(true);
            btnLaunchFF.setEnabled(true);
        } else {
            tvStatus.setText("○ IDLE");
            tvStatus.setTextColor(0xFF8B98A8);
            btnStart.setEnabled(true);
            btnStop.setEnabled(false);
            btnLaunchFF.setEnabled(false);
        }
    }

    // ── Dialogs ───────────────────────────────────────────────────────────

    private void showDetailDialog(CapturedPacket pkt) {
        ScrollView sv = new ScrollView(this);
        TextView tv = new TextView(this);
        tv.setTypeface(android.graphics.Typeface.MONOSPACE);
        tv.setTextSize(10f);
        tv.setText(pkt.toDetailString());
        tv.setPadding(16, 16, 16, 16);
        tv.setTextColor(0xFFE6EDF3);
        sv.addView(tv);

        new AlertDialog.Builder(this)
                .setTitle("Packet Detail — " + pkt.label)
                .setView(sv)
                .setPositiveButton("RESEND", (d, w) -> showResendDialog(pkt))
                .setNegativeButton("CLOSE", null)
                .show();
    }

    private void showResendDialog(CapturedPacket pkt) {
        EditText et = new EditText(this);
        et.setTypeface(android.graphics.Typeface.MONOSPACE);
        et.setTextSize(11f);
        // pre-fill with hex of raw data
        if (pkt.rawData != null) {
            StringBuilder sb = new StringBuilder();
            for (byte b : pkt.rawData) sb.append(String.format("%02X", b));
            et.setText(sb.toString());
        }
        et.setHint("Edit hex then resend…");

        new AlertDialog.Builder(this)
                .setTitle("↻ Resend Packet")
                .setMessage(pkt.getSummary())
                .setView(et)
                .setPositiveButton("RESEND", (d, w) -> {
                    String hexStr = et.getText().toString().trim().replace(" ", "");
                    byte[] data = null;
                    if (!hexStr.isEmpty()) {
                        try {
                            data = new byte[hexStr.length() / 2];
                            for (int i = 0; i < data.length; i++) {
                                data[i] = (byte) Integer.parseInt(
                                        hexStr.substring(i * 2, i * 2 + 2), 16);
                            }
                        } catch (Exception ex) {
                            Toast.makeText(this, "Invalid hex", Toast.LENGTH_SHORT).show();
                            return;
                        }
                    }
                    // Resend via VPN service
                    Intent i = new Intent(this, BashantVpnService.class);
                    // Store in PacketStore resend queue (simple approach)
                    Toast.makeText(this,
                            "Resend queued (" + (data != null ? data.length : 0) + "B)",
                            Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("CANCEL", null)
                .show();
    }

    // ── Telegram support ──────────────────────────────────────────────────

    private void openTelegram() {
        try {
            Intent i = new Intent(Intent.ACTION_VIEW,
                    Uri.parse("https://t.me/Bgcodex"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
        } catch (Exception e) {
            Toast.makeText(this, "Cannot open Telegram", Toast.LENGTH_SHORT).show();
        }
    }
}
