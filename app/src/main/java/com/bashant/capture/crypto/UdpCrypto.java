package com.bashant.capture.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.zip.CRC32;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * FF UDP encryption — ported directly from ZestyXGlory/ff_udp.py
 *
 * Implements:
 *   - TEA cipher (CFB-CBC hybrid, 16 rounds) for game packets
 *   - AES-128-CBC for auth datagrams
 *   - CRC-7 for packet header integrity
 *   - Packet encode / decode matching the wire format
 */
public class UdpCrypto {

    // ── TEA constants ──────────────────────────────────────────────────────
    private static final long  DELTA        = 0x9E3779B9L;
    private static final int   ROUNDS       = 16;
    private static final int   SALT_LEN     = 2;
    private static final int   ZERO_LEN     = 7;

    // ── Packet framing ─────────────────────────────────────────────────────
    public static final int    MTU_LIMIT    = 1300;
    public static final int    HDR_SIZE_UNRELIABLE = 8;
    public static final int    HDR_SIZE_RELIABLE   = 10;
    public static final int    MSG_KEY_MIN  = 90;
    public static final int    MSG_KEY_MID  = 100;
    public static final int    MSG_KEY_MAX  = 110;
    public static final int    FLAG_ENCRYPTED = 1;

    // ── Auth AES constants (captured OB55 values, same as ff_udp.py) ──────
    private static final byte[] AUTH_AES_KEY = {
        0x19, 0x47, (byte)0xB9, 0x74, (byte)0xD9, 0x73, (byte)0xF3, 0x7F,
        0x42, 0x06, 0x01, 0x38, 0x42, 0x00, 0x10, 0x30
    };
    private static final byte[] AUTH_AES_IV = {
        0x28, 0x7F, (byte)0xCA, 0x7A, (byte)0xF9, 0x67, (byte)0xF3, 0x7A,
        0x65, 0x02, 0x01, 0x10, 0x40, 0x40, 0x00, 0x30
    };

    // ── CRC-7 lookup ───────────────────────────────────────────────────────
    private static final int[] CRC7_TABLE = buildCrc7Table();

    private static int[] buildCrc7Table() {
        int[] t = new int[256];
        for (int b = 0; b < 256; b++) {
            int c = 0;
            for (int i = 0; i < 8; i++) {
                int top = ((c >> 6) & 1) ^ ((b >> (7 - i)) & 1);
                c = (c << 1) & 0x7F;
                if (top != 0) c ^= 0x09;
            }
            t[b] = c;
        }
        return t;
    }

    public static int crc7Byte(int crc, int b) {
        return CRC7_TABLE[((crc << 1) ^ (b & 0xFF)) & 0xFF];
    }

    public static int crc7U16(int crc, int v) {
        return crc7Byte(crc7Byte(crc, v & 0xFF), (v >> 8) & 0xFF);
    }

    public static int crc7Buf(int crc, byte[] data, int off, int len) {
        for (int i = off; i < off + len; i++) {
            crc = CRC7_TABLE[((crc << 1) ^ (data[i] & 0xFF)) & 0xFF];
        }
        return crc;
    }

    // ── TEA encrypt / decrypt ──────────────────────────────────────────────

    private static byte[] teaEncBlock(byte[] blk, long[] k) {
        ByteBuffer bb = ByteBuffer.wrap(blk).order(ByteOrder.LITTLE_ENDIAN);
        long y = bb.getInt() & 0xFFFFFFFFL;
        long z = bb.getInt() & 0xFFFFFFFFL;
        long s = 0;
        for (int i = 0; i < ROUNDS; i++) {
            s = (s + DELTA) & 0xFFFFFFFFL;
            y = (y + ((((z << 4) & 0xFFFFFFFFL) + k[0]) ^ (z + s) ^ ((z >> 5) + k[1]))) & 0xFFFFFFFFL;
            z = (z + ((((y << 4) & 0xFFFFFFFFL) + k[2]) ^ (y + s) ^ ((y >> 5) + k[3]))) & 0xFFFFFFFFL;
        }
        ByteBuffer out = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        out.putInt((int)(y & 0xFFFFFFFFL));
        out.putInt((int)(z & 0xFFFFFFFFL));
        return out.array();
    }

    private static byte[] teaDecBlock(byte[] blk, long[] k) {
        ByteBuffer bb = ByteBuffer.wrap(blk).order(ByteOrder.LITTLE_ENDIAN);
        long y = bb.getInt() & 0xFFFFFFFFL;
        long z = bb.getInt() & 0xFFFFFFFFL;
        long s = (DELTA << 4) & 0xFFFFFFFFL;
        for (int i = 0; i < ROUNDS; i++) {
            z = (z - ((((y << 4) & 0xFFFFFFFFL) + k[2]) ^ (y + s) ^ ((y >> 5) + k[3]))) & 0xFFFFFFFFL;
            y = (y - ((((z << 4) & 0xFFFFFFFFL) + k[0]) ^ (z + s) ^ ((z >> 5) + k[1]))) & 0xFFFFFFFFL;
            s = (s - DELTA) & 0xFFFFFFFFL;
        }
        ByteBuffer out = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        out.putInt((int)(y & 0xFFFFFFFFL));
        out.putInt((int)(z & 0xFFFFFFFFL));
        return out.array();
    }

    private static long[] keyToLongs(byte[] key) {
        ByteBuffer bb = ByteBuffer.wrap(key, 0, 16).order(ByteOrder.LITTLE_ENDIAN);
        return new long[]{
            bb.getInt() & 0xFFFFFFFFL,
            bb.getInt() & 0xFFFFFFFFL,
            bb.getInt() & 0xFFFFFFFFL,
            bb.getInt() & 0xFFFFFFFFL
        };
    }

    public static int teaEncryptLen(int n) {
        int t = 1 + SALT_LEN + n + ZERO_LEN;
        int r = t % 8;
        return r == 0 ? t : t + (8 - r);
    }

    public static byte[] teaEncrypt(byte[] data, byte[] key) {
        long[] k = keyToLongs(key);
        int n = teaEncryptLen(data.length);
        int pad = n - (1 + SALT_LEN + data.length + ZERO_LEN);
        byte[] plain = new byte[n];
        plain[0] = (byte) pad;
        System.arraycopy(data, 0, plain, 1 + pad + SALT_LEN, data.length);

        byte[] out = new byte[n];
        byte[] ivP = new byte[8];
        byte[] ivC = new byte[8];
        for (int off = 0; off < n; off += 8) {
            byte[] blk = new byte[8];
            for (int i = 0; i < 8; i++) blk[i] = (byte)(plain[off + i] ^ ivC[i]);
            byte[] c = teaEncBlock(blk, k);
            for (int i = 0; i < 8; i++) c[i] ^= ivP[i];
            System.arraycopy(c, 0, out, off, 8);
            ivP = blk; ivC = c;
        }
        return out;
    }

    public static byte[] teaDecrypt(byte[] buf, byte[] key) {
        if (buf.length < 16 || buf.length % 8 != 0) return null;
        long[] k = keyToLongs(key);
        int pad = teaDecBlock(Arrays.copyOf(buf, 8), k)[0] & 7;
        int outLen = buf.length - pad - 1 - SALT_LEN - ZERO_LEN;
        if (outLen < 0) return null;

        byte[] plain = new byte[buf.length];
        byte[] ivP = new byte[8];
        byte[] ivC = new byte[8];
        for (int off = 0; off < buf.length; off += 8) {
            byte[] c = Arrays.copyOfRange(buf, off, off + 8);
            byte[] t = new byte[8];
            for (int i = 0; i < 8; i++) t[i] = (byte)(c[i] ^ ivP[i]);
            byte[] blk = teaDecBlock(t, k);
            for (int i = 0; i < 8; i++) plain[off + i] = (byte)(blk[i] ^ ivC[i]);
            ivP = blk; ivC = c;
        }
        // verify zero tail
        int at = 1 + pad + SALT_LEN;
        for (int i = at + outLen; i < at + outLen + ZERO_LEN && i < plain.length; i++) {
            if (plain[i] != 0) return null;
        }
        return Arrays.copyOfRange(plain, at, at + outLen);
    }

    // ── AES-128-CBC (auth packets) ─────────────────────────────────────────

    public static byte[] aesEncrypt(byte[] data, byte[] key, byte[] iv) {
        try {
            int pad = 16 - (data.length % 16);
            byte[] padded = new byte[data.length + pad];
            System.arraycopy(data, 0, padded, 0, data.length);
            Arrays.fill(padded, data.length, padded.length, (byte) pad);
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE,
                   new SecretKeySpec(key, "AES"),
                   new IvParameterSpec(iv));
            return c.doFinal(padded);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] aesDecrypt(byte[] data, byte[] key, byte[] iv) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.DECRYPT_MODE,
                   new SecretKeySpec(key, "AES"),
                   new IvParameterSpec(iv));
            byte[] plain = c.doFinal(data);
            if (plain.length == 0) return plain;
            int pad = plain[plain.length - 1] & 0xFF;
            if (pad > 0 && pad <= 16) return Arrays.copyOf(plain, plain.length - pad);
            return plain;
        } catch (Exception e) {
            return null;
        }
    }

    /** Encrypt with captured OB55 auth key/IV */
    public static byte[] authAesEncrypt(byte[] data) {
        return aesEncrypt(data, AUTH_AES_KEY, AUTH_AES_IV);
    }

    public static byte[] authAesDecrypt(byte[] data) {
        return aesDecrypt(data, AUTH_AES_KEY, AUTH_AES_IV);
    }

    // ── Packet decode ──────────────────────────────────────────────────────

    public static DecodedPacket decodePacket(byte[] pkt, byte[] key, int[] order) {
        if (pkt.length < HDR_SIZE_UNRELIABLE) return null;
        int k0 = key[0] & 0xFF;
        int kk = k0 | (k0 << 8);
        int msgKey = pkt[0] & 0xFF;
        int crc    = pkt[1] & 0xFF;
        if (msgKey < MSG_KEY_MIN || msgKey > MSG_KEY_MAX) return null;
        if (crc7Buf(0, pkt, 2, pkt.length - 2) != crc) return null;

        boolean reliable = msgKey < MSG_KEY_MID;
        int hdr = reliable ? HDR_SIZE_RELIABLE : HDR_SIZE_UNRELIABLE;
        if (pkt.length < hdr) return null;

        int[] FIELD_SIZE = {1, 2, 2, 1, 2};
        int[] f = new int[5];
        int off = 2;
        for (int fid : order) {
            if (fid == 2 && !reliable) continue; // F_ORDERID skipped for unreliable
            if (FIELD_SIZE[fid] == 1) {
                f[fid] = (pkt[off] & 0xFF) ^ k0;
                off++;
            } else {
                int v = ((pkt[off] & 0xFF) | ((pkt[off + 1] & 0xFF) << 8)) ^ kk;
                f[fid] = v;
                off += 2;
            }
        }
        byte[] payload = Arrays.copyOfRange(pkt, hdr, pkt.length);
        byte[] body;
        if ((f[3] & FLAG_ENCRYPTED) != 0) {
            body = teaDecrypt(payload, key);
        } else {
            body = payload;
        }
        return new DecodedPacket(msgKey, f[1], f[2], f[3], f[0], f[4], reliable, body, payload);
    }

    public static byte[] encodePacket(int cmd, int sendOption, int orderId,
                                       int flags, byte[] body, byte[] key, int[] order) {
        int k0 = key[0] & 0xFF;
        int kk = k0 | (k0 << 8);
        boolean reliable = isReliable(cmd, sendOption);
        byte[] payload = (flags & FLAG_ENCRYPTED) != 0 ? teaEncrypt(body, key) : body;

        int[] FIELD_SIZE = {1, 2, 2, 1, 2};
        int[] masked = {
            sendOption ^ k0,
            cmd        ^ kk,
            orderId    ^ kk,
            flags      ^ k0,
            payload.length ^ kk
        };

        java.util.Random rng = new java.util.Random();
        int msgKey = reliable
            ? (MSG_KEY_MIN + rng.nextInt(MSG_KEY_MID - MSG_KEY_MIN))
            : (MSG_KEY_MID + rng.nextInt(MSG_KEY_MAX - MSG_KEY_MID));

        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        bos.write(msgKey);
        bos.write(0); // crc placeholder
        int crc = 0;
        for (int fid : order) {
            if (fid == 2 && !reliable) continue;
            int v = masked[fid];
            if (FIELD_SIZE[fid] == 1) {
                crc = crc7Byte(crc, v);
                bos.write(v);
            } else {
                crc = crc7U16(crc, v);
                bos.write(v & 0xFF);
                bos.write((v >> 8) & 0xFF);
            }
        }
        try { bos.write(payload); } catch (Exception ignored) {}
        byte[] out = bos.toByteArray();
        // fill crc over everything after byte[1]
        out[1] = (byte) crc7Buf(crc, payload, 0, payload.length);
        return out;
    }

    public static boolean isReliable(int cmd, int sendOption) {
        if (cmd == 2 || sendOption < 1 || sendOption > 5) return false;
        return ((0x13 >> (sendOption - 1)) & 1) != 0;
    }

    public static int[] defaultOrder() {
        return new int[]{0, 1, 2, 3, 4};
    }

    // ── Data classes ───────────────────────────────────────────────────────

    public static class DecodedPacket {
        public final int msgKey, cmd, orderId, flags, sendOption, length;
        public final boolean reliable;
        public final byte[] body;
        public final byte[] rawPayload;

        public DecodedPacket(int msgKey, int cmd, int orderId, int flags,
                              int sendOption, int length, boolean reliable,
                              byte[] body, byte[] rawPayload) {
            this.msgKey     = msgKey;
            this.cmd        = cmd;
            this.orderId    = orderId;
            this.flags      = flags;
            this.sendOption = sendOption;
            this.length     = length;
            this.reliable   = reliable;
            this.body       = body;
            this.rawPayload = rawPayload;
        }

        @Override
        public String toString() {
            return String.format("Pkt{cmd=%d so=%d oid=%d flags=0x%02x rel=%b body=%dB}",
                cmd, sendOption, orderId, flags, reliable, body != null ? body.length : 0);
        }
    }
}
