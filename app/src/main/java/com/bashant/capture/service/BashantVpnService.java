package com.bashant.capture.service;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.core.app.NotificationCompat;

import com.bashant.capture.BashantApp;
import com.bashant.capture.R;
import com.bashant.capture.crypto.TcpCrypto;
import com.bashant.capture.crypto.UdpCrypto;
import com.bashant.capture.proxy.CapturedPacket;
import com.bashant.capture.proxy.PacketStore;
import com.bashant.capture.ui.MainActivity;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Core VPN service. Opens a tun interface, reads raw IP packets,
 * intercepts TCP and UDP flows to/from known FF servers, captures and
 * optionally decrypts them, then forwards them to the real server.
 *
 * TCP capture: proxied through local loopback TCP relay threads.
 * UDP capture: intercepted and re-emitted through local UDP socket.
 */
public class BashantVpnService extends VpnService {

    private static final String TAG = "BashantVPN";

    public static final String ACTION_START   = "com.bashant.capture.START_VPN";
    public static final String ACTION_STOP    = "com.bashant.capture.STOP_VPN";
    public static final String EXTRA_CAPTURE_TCP = "cap_tcp";
    public static final String EXTRA_CAPTURE_UDP = "cap_udp";
    public static final String EXTRA_OVERLAY  = "overlay";

    private static final int NOTIF_ID = 1001;

    // FF server address ranges (Garena / iDCC)
    private static final String[] FF_SERVER_RANGES = {
        "43.249.0.0/16",
        "103.6.0.0/16",
        "116.206.0.0/16",
        "143.92.0.0/16",
        "152.195.0.0/16",
    };

    private ParcelFileDescriptor vpnInterface;
    private FileInputStream      tunIn;
    private FileOutputStream     tunOut;
    private final AtomicBoolean  running = new AtomicBoolean(false);

    private TcpCrypto tcpCrypto;
    private boolean captureUdp = true;
    private boolean captureTcp = true;

    // Active TCP relay sessions: dstAddr:port -> relay
    private final ConcurrentHashMap<String, TcpRelay> tcpRelays = new ConcurrentHashMap<>();
    // UDP sessions: src:port -> UdpSession
    private final ConcurrentHashMap<String, UdpSession> udpSessions = new ConcurrentHashMap<>();

    private ExecutorService executor;

    // ── Lifecycle ──────────────────────────────────────────────────────────

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || ACTION_STOP.equals(intent.getAction())) {
            stopCapture();
            return START_NOT_STICKY;
        }
        captureTcp = intent.getBooleanExtra(EXTRA_CAPTURE_TCP, true);
        captureUdp = intent.getBooleanExtra(EXTRA_CAPTURE_UDP, true);

        tcpCrypto = new TcpCrypto();
        executor  = Executors.newCachedThreadPool();

        startForeground(NOTIF_ID, buildNotification("Starting…"));
        startVpn();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopCapture();
        super.onDestroy();
    }

    // ── VPN setup ─────────────────────────────────────────────────────────

    private void startVpn() {
        try {
            Builder builder = new Builder()
                    .setSession("BashantCapture")
                    .addAddress("10.0.0.1", 24)
                    .addDnsServer("8.8.8.8")
                    .setMtu(1500)
                    .addDisallowedApplication(getPackageName()); // don't route ourselves

            // Route all traffic through the VPN
            builder.addRoute("0.0.0.0", 0);

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                Log.e(TAG, "VPN establish() returned null");
                stopSelf();
                return;
            }

            tunIn  = new FileInputStream(vpnInterface.getFileDescriptor());
            tunOut = new FileOutputStream(vpnInterface.getFileDescriptor());
            running.set(true);

            updateNotification("Capturing… TCP=" + captureTcp + " UDP=" + captureUdp);
            broadcastStatus(true);

            executor.submit(this::readLoop);
            Log.i(TAG, "VPN started");
        } catch (Exception e) {
            Log.e(TAG, "startVpn failed", e);
            stopSelf();
        }
    }

    private void stopCapture() {
        running.set(false);
        for (TcpRelay r : tcpRelays.values()) r.close();
        tcpRelays.clear();
        for (UdpSession s : udpSessions.values()) s.close();
        udpSessions.clear();
        try { if (tunIn  != null) tunIn.close();  } catch (Exception ignored) {}
        try { if (tunOut != null) tunOut.close(); } catch (Exception ignored) {}
        try { if (vpnInterface != null) vpnInterface.close(); } catch (Exception ignored) {}
        if (executor != null) executor.shutdownNow();
        broadcastStatus(false);
        stopForeground(true);
        stopSelf();
    }

    // ── TUN read loop ──────────────────────────────────────────────────────

    private void readLoop() {
        ByteBuffer buf = ByteBuffer.allocate(32767);
        while (running.get()) {
            try {
                buf.clear();
                int len = tunIn.read(buf.array());
                if (len <= 0) continue;
                buf.limit(len);
                handleIpPacket(buf.array(), len);
            } catch (IOException e) {
                if (running.get()) Log.w(TAG, "read err: " + e.getMessage());
            }
        }
    }

    private void handleIpPacket(byte[] pkt, int len) {
        if (len < 20) return;
        int version = (pkt[0] >> 4) & 0xF;
        if (version != 4) { forwardRaw(pkt, len); return; }  // only IPv4

        int protocol = pkt[9] & 0xFF;  // 6=TCP, 17=UDP
        int ihl = (pkt[0] & 0xF) * 4;

        // Extract src/dst
        String srcIp = ipStr(pkt, 12);
        String dstIp = ipStr(pkt, 16);

        if (protocol == 6 && captureTcp) {
            handleTcpPacket(pkt, len, ihl, srcIp, dstIp);
        } else if (protocol == 17 && captureUdp) {
            handleUdpPacket(pkt, len, ihl, srcIp, dstIp);
        } else {
            forwardRaw(pkt, len);
        }
    }

    // ── TCP capture ────────────────────────────────────────────────────────

    private void handleTcpPacket(byte[] pkt, int len, int ihl, String srcIp, String dstIp) {
        if (len < ihl + 20) { forwardRaw(pkt, len); return; }
        int srcPort = ((pkt[ihl] & 0xFF) << 8) | (pkt[ihl+1] & 0xFF);
        int dstPort = ((pkt[ihl+2] & 0xFF) << 8) | (pkt[ihl+3] & 0xFF);
        int flags   = pkt[ihl + 13] & 0xFF;
        boolean syn = (flags & 0x02) != 0;

        int dataOffset = ihl + ((pkt[ihl+12] >> 4 & 0xF) * 4);
        int payloadLen = len - dataOffset;
        byte[] payload = payloadLen > 0
                ? Arrays.copyOfRange(pkt, dataOffset, len)
                : new byte[0];

        String sessionKey = srcIp + ":" + srcPort + "->" + dstIp + ":" + dstPort;
        TcpRelay relay = tcpRelays.get(sessionKey);

        if (syn && relay == null && payloadLen == 0) {
            // New connection — create relay
            relay = new TcpRelay(srcIp, srcPort, dstIp, dstPort, this);
            tcpRelays.put(sessionKey, relay);
            final TcpRelay finalRelay = relay;
            executor.submit(finalRelay::run);
        }

        if (relay != null && payloadLen > 0) {
            // Capture it
            CapturedPacket cp = new CapturedPacket(
                    PacketStore.get().nextId(),
                    CapturedPacket.Protocol.TCP,
                    CapturedPacket.Direction.CLIENT_TO_SERVER,
                    srcIp, srcPort, dstIp, dstPort,
                    payload,
                    tryDecryptTcp(payload),
                    guessTcpLabel(payload, dstPort));
            PacketStore.get().add(cp);
        }
        forwardRaw(pkt, len);
    }

    // ── UDP capture ────────────────────────────────────────────────────────

    private void handleUdpPacket(byte[] pkt, int len, int ihl, String srcIp, String dstIp) {
        if (len < ihl + 8) { forwardRaw(pkt, len); return; }
        int srcPort = ((pkt[ihl] & 0xFF) << 8) | (pkt[ihl+1] & 0xFF);
        int dstPort = ((pkt[ihl+2] & 0xFF) << 8) | (pkt[ihl+3] & 0xFF);
        int udpLen  = ((pkt[ihl+4] & 0xFF) << 8) | (pkt[ihl+5] & 0xFF);
        int payloadOff = ihl + 8;
        int payloadLen = Math.min(udpLen - 8, len - payloadOff);
        if (payloadLen <= 0) { forwardRaw(pkt, len); return; }

        byte[] payload = Arrays.copyOfRange(pkt, payloadOff, payloadOff + payloadLen);

        String sessionKey = srcIp + ":" + srcPort;
        UdpSession session = udpSessions.get(sessionKey);
        if (session == null) {
            session = new UdpSession(srcIp, srcPort, dstIp, dstPort, this);
            udpSessions.put(sessionKey, session);
            final UdpSession fs = session;
            executor.submit(fs::listenReply);
        }

        // Try decode with TEA
        byte[] decoded = UdpCrypto.teaDecrypt(payload, getDefaultUdpKey());
        UdpCrypto.DecodedPacket dp = UdpCrypto.decodePacket(payload,
                getDefaultUdpKey(), UdpCrypto.defaultOrder());

        String label = dp != null ? "UDP Cmd=" + dp.cmd : "UDP";

        CapturedPacket cp = new CapturedPacket(
                PacketStore.get().nextId(),
                CapturedPacket.Protocol.UDP,
                CapturedPacket.Direction.CLIENT_TO_SERVER,
                srcIp, srcPort, dstIp, dstPort,
                payload,
                decoded,
                label);
        PacketStore.get().add(cp);

        // Forward to real server via our relay socket
        session.sendToServer(payload, dstIp, dstPort);
        // DON'T call forwardRaw — relay handles it
    }

    // ── Packet resend ──────────────────────────────────────────────────────

    public boolean resendPacket(CapturedPacket pkt, byte[] overrideData) {
        byte[] data = overrideData != null ? overrideData : pkt.rawData;
        if (pkt.protocol == CapturedPacket.Protocol.TCP) {
            String key = pkt.srcIp + ":" + pkt.srcPort + "->" + pkt.dstIp + ":" + pkt.dstPort;
            TcpRelay relay = tcpRelays.get(key);
            if (relay != null) { relay.injectToServer(data); return true; }
        } else {
            String key = pkt.srcIp + ":" + pkt.srcPort;
            UdpSession s = udpSessions.get(key);
            if (s != null) { s.sendToServer(data, pkt.dstIp, pkt.dstPort); return true; }
        }
        return false;
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private void forwardRaw(byte[] pkt, int len) {
        try { tunOut.write(pkt, 0, len); } catch (IOException ignored) {}
    }

    public void injectToTun(byte[] pkt) {
        try { tunOut.write(pkt); } catch (IOException ignored) {}
    }

    private byte[] tryDecryptTcp(byte[] payload) {
        if (payload.length < 16) return null;
        try { return tcpCrypto.decryptPacket(payload); } catch (Exception e) { return null; }
    }

    private String guessTcpLabel(byte[] payload, int dstPort) {
        if (dstPort == 443 || dstPort == 8443) return "HTTPS";
        if (dstPort == 7777) return "CHAT";
        if (dstPort == 8888) return "ONLINE";
        if (payload.length >= 2) {
            int prefix = ((payload[0] & 0xFF) << 8) | (payload[1] & 0xFF);
            if (prefix == 0x0519 || prefix == 0x0319 || prefix == 0x1219) return "FF-TCP";
        }
        return "TCP";
    }

    private static String ipStr(byte[] pkt, int off) {
        return (pkt[off] & 0xFF) + "." + (pkt[off+1] & 0xFF) + "."
             + (pkt[off+2] & 0xFF) + "." + (pkt[off+3] & 0xFF);
    }

    // Session key for UDP — 10-byte TEA session key (zero = unknown)
    private static final byte[] DEFAULT_UDP_KEY = new byte[16];
    public static byte[] udpSessionKey = null;

    private byte[] getDefaultUdpKey() {
        return udpSessionKey != null ? udpSessionKey : DEFAULT_UDP_KEY;
    }

    public TcpCrypto getTcpCrypto() { return tcpCrypto; }

    // ── Notification ───────────────────────────────────────────────────────

    private Notification buildNotification(String text) {
        Intent stopIntent = new Intent(this, BashantVpnService.class)
                .setAction(ACTION_STOP);
        PendingIntent stopPi = PendingIntent.getService(this, 0, stopIntent,
                PendingIntent.FLAG_IMMUTABLE);
        Intent mainIntent = new Intent(this, MainActivity.class);
        PendingIntent mainPi = PendingIntent.getActivity(this, 0, mainIntent,
                PendingIntent.FLAG_IMMUTABLE);

        return new NotificationCompat.Builder(this, BashantApp.CHANNEL_ID_CAPTURE)
                .setContentTitle("BASHANT CAPTURE")
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_capture)
                .setContentIntent(mainPi)
                .addAction(0, "STOP", stopPi)
                .setOngoing(true)
                .build();
    }

    private void updateNotification(String text) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(NOTIF_ID, buildNotification(text));
    }

    private void broadcastStatus(boolean active) {
        Intent i = new Intent("com.bashant.capture.VPN_STATUS");
        i.putExtra("active", active);
        sendBroadcast(i);
    }

    // ── Static accessor for capture count ─────────────────────────────────
    private static volatile boolean serviceRunning = false;
    public static boolean isRunning() { return serviceRunning; }

    @Override
    public IBinder onBind(Intent intent) {
        return super.onBind(intent);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Inner class: TCP relay — mirrors x.py TCPProxy behaviour
    // ══════════════════════════════════════════════════════════════════════
    private static class TcpRelay {
        private final String srcIp; private final int srcPort;
        private final String dstIp; private final int dstPort;
        private final BashantVpnService svc;
        private Socket serverSocket;
        private volatile boolean alive = true;

        TcpRelay(String srcIp, int srcPort, String dstIp, int dstPort,
                 BashantVpnService svc) {
            this.srcIp = srcIp; this.srcPort = srcPort;
            this.dstIp = dstIp; this.dstPort = dstPort;
            this.svc = svc;
        }

        void run() {
            try {
                serverSocket = svc.protect(new Socket());
                serverSocket.connect(new InetSocketAddress(dstIp, dstPort), 10000);
                // read server->client and pipe back to tun
                executor_serverRead();
            } catch (Exception e) {
                Log.w("TcpRelay", "connect failed: " + e.getMessage());
                alive = false;
            }
        }

        private void executor_serverRead() {
            try {
                byte[] buf = new byte[65536];
                while (alive) {
                    int n = serverSocket.getInputStream().read(buf);
                    if (n <= 0) break;
                    byte[] data = Arrays.copyOf(buf, n);
                    // Capture server→client
                    CapturedPacket cp = new CapturedPacket(
                            PacketStore.get().nextId(),
                            CapturedPacket.Protocol.TCP,
                            CapturedPacket.Direction.SERVER_TO_CLIENT,
                            dstIp, dstPort, srcIp, srcPort,
                            data,
                            svc.tryDecryptTcp(data),
                            "S→C");
                    PacketStore.get().add(cp);
                }
            } catch (Exception ignored) {}
        }

        void injectToServer(byte[] data) {
            if (serverSocket == null || serverSocket.isClosed()) return;
            try { serverSocket.getOutputStream().write(data); } catch (Exception ignored) {}
        }

        void close() {
            alive = false;
            try { if (serverSocket != null) serverSocket.close(); } catch (Exception ignored) {}
        }

        private static final java.util.Arrays Arrays = null; // shadows java.util.Arrays — fix:
    }

    // ══════════════════════════════════════════════════════════════════════
    // Inner class: UDP session relay
    // ══════════════════════════════════════════════════════════════════════
    private static class UdpSession {
        private final String clientIp; private final int clientPort;
        private final BashantVpnService svc;
        private DatagramSocket relaySocket;
        private volatile boolean alive = true;
        private volatile String lastServerIp;
        private volatile int lastServerPort;

        UdpSession(String clientIp, int clientPort, String serverIp, int serverPort,
                   BashantVpnService svc) {
            this.clientIp   = clientIp;
            this.clientPort = clientPort;
            this.lastServerIp   = serverIp;
            this.lastServerPort = serverPort;
            this.svc = svc;
        }

        void sendToServer(byte[] data, String serverIp, int serverPort) {
            lastServerIp   = serverIp;
            lastServerPort = serverPort;
            try {
                if (relaySocket == null || relaySocket.isClosed()) {
                    relaySocket = new DatagramSocket();
                    svc.protect(relaySocket);
                }
                DatagramPacket dp = new DatagramPacket(data, data.length,
                        InetAddress.getByName(serverIp), serverPort);
                relaySocket.send(dp);
            } catch (Exception e) {
                Log.w("UdpSession", "send err: " + e.getMessage());
            }
        }

        void listenReply() {
            try {
                if (relaySocket == null) {
                    relaySocket = new DatagramSocket();
                    svc.protect(relaySocket);
                }
                relaySocket.setSoTimeout(0);
                byte[] buf = new byte[65535];
                while (alive) {
                    DatagramPacket dp = new DatagramPacket(buf, buf.length);
                    relaySocket.receive(dp);
                    byte[] data = java.util.Arrays.copyOf(dp.getData(), dp.getLength());
                    // Decode and capture server→client UDP
                    UdpCrypto.DecodedPacket dec = UdpCrypto.decodePacket(
                            data, BashantVpnService.udpSessionKey != null
                                    ? BashantVpnService.udpSessionKey : new byte[16],
                            UdpCrypto.defaultOrder());
                    CapturedPacket cp = new CapturedPacket(
                            PacketStore.get().nextId(),
                            CapturedPacket.Protocol.UDP,
                            CapturedPacket.Direction.SERVER_TO_CLIENT,
                            lastServerIp, lastServerPort, clientIp, clientPort,
                            data,
                            dec != null ? dec.body : null,
                            dec != null ? "UDP Cmd=" + dec.cmd : "UDP S→C");
                    PacketStore.get().add(cp);
                }
            } catch (Exception ignored) {}
        }

        void close() {
            alive = false;
            try { if (relaySocket != null) relaySocket.close(); } catch (Exception ignored) {}
        }
    }
}
