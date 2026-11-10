package com.bashant.capture.proxy;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class CapturedPacket {

    public enum Protocol { TCP, UDP }
    public enum Direction { CLIENT_TO_SERVER, SERVER_TO_CLIENT }

    private static final SimpleDateFormat SDF =
            new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);

    public final long      id;
    public final long      timestamp;
    public final Protocol  protocol;
    public final Direction direction;
    public final String    srcIp;
    public final int       srcPort;
    public final String    dstIp;
    public final int       dstPort;
    public final byte[]    rawData;
    public final byte[]    decryptedData;   // null if not decrypted
    public final String    label;           // e.g. "MajorLogin", "UDP Cmd=1"

    public CapturedPacket(long id, Protocol protocol, Direction direction,
                          String srcIp, int srcPort, String dstIp, int dstPort,
                          byte[] rawData, byte[] decryptedData, String label) {
        this.id            = id;
        this.timestamp     = System.currentTimeMillis();
        this.protocol      = protocol;
        this.direction     = direction;
        this.srcIp         = srcIp;
        this.srcPort       = srcPort;
        this.dstIp         = dstIp;
        this.dstPort       = dstPort;
        this.rawData       = rawData;
        this.decryptedData = decryptedData;
        this.label         = label;
    }

    public String getTimestampStr() {
        return SDF.format(new Date(timestamp));
    }

    public String toHex(byte[] data) {
        if (data == null) return "(null)";
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X ", b));
        return sb.toString().trim();
    }

    public String getSummary() {
        return String.format("[%s] %s %s %s:%d → %s:%d  %dB%s",
                getTimestampStr(),
                protocol.name(),
                direction == Direction.CLIENT_TO_SERVER ? "▲" : "▼",
                srcIp, srcPort,
                dstIp, dstPort,
                rawData != null ? rawData.length : 0,
                label != null && !label.isEmpty() ? "  [" + label + "]" : "");
    }

    public String toDetailString() {
        StringBuilder sb = new StringBuilder();
        sb.append("══════════════════════════════════════\n");
        sb.append(getSummary()).append("\n");
        sb.append("──────────────────────────────────────\n");
        sb.append("RAW HEX:\n").append(toHex(rawData)).append("\n");
        if (decryptedData != null) {
            sb.append("DECRYPTED HEX:\n").append(toHex(decryptedData)).append("\n");
        }
        return sb.toString();
    }
}
