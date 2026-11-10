package com.bashant.capture.crypto;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * TCP packet AES-CBC crypto — ported from x.py decrypt_raw_packet()
 * Tries offsets 6,0,1..15 to find the encrypted block boundary.
 */
public class TcpCrypto {

    // Default FF AES key/IV from x.py
    private static final byte[] DEFAULT_KEY = {
        89, 103, 38, 116, 99, 37, 68, 69,
        117, 104, 54, 37, 90, 99, 94, 56
    };
    private static final byte[] DEFAULT_IV = {
        54, 111, 121, 90, 68, 114, 50, 50,
        69, 51, 121, 99, 104, 106, 77, 37
    };

    private byte[] currentKey;
    private byte[] currentIv;

    public TcpCrypto() {
        currentKey = DEFAULT_KEY.clone();
        currentIv  = DEFAULT_IV.clone();
    }

    public void setKeyIv(byte[] key, byte[] iv) {
        if (key != null && (key.length == 16 || key.length == 24 || key.length == 32))
            currentKey = key.clone();
        if (iv != null && iv.length == 16)
            currentIv = iv.clone();
    }

    public byte[] getKey() { return currentKey.clone(); }
    public byte[] getIv()  { return currentIv.clone();  }

    /**
     * Decrypt a raw TCP packet — tries offsets 6,0,1..15 to find block boundary.
     * Direct port of x.py decrypt_raw_packet().
     */
    public byte[] decryptPacket(byte[] raw) {
        return decryptPacket(raw, currentKey, currentIv);
    }

    public static byte[] decryptPacket(byte[] raw, byte[] key, byte[] iv) {
        int[] offsets = {6, 0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        byte[] encrypted = null;

        for (int offset : offsets) {
            byte[] test = Arrays.copyOfRange(raw, offset, raw.length);
            if (test.length >= 16 && test.length % 16 == 0) {
                encrypted = test;
                if (offset == 6) break; // preferred offset
            }
        }

        if (encrypted == null) {
            encrypted = raw;
            if (encrypted.length % 16 != 0) {
                int pad = 16 - (encrypted.length % 16);
                byte[] padded = Arrays.copyOf(encrypted, encrypted.length + pad);
                encrypted = padded;
            }
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(key, "AES"),
                        new IvParameterSpec(iv));
            byte[] decryptedPadded = cipher.doFinal(encrypted);
            // try unpad
            if (decryptedPadded.length > 0) {
                int padByte = decryptedPadded[decryptedPadded.length - 1] & 0xFF;
                if (padByte >= 1 && padByte <= 16) {
                    return Arrays.copyOf(decryptedPadded, decryptedPadded.length - padByte);
                }
            }
            return decryptedPadded;
        } catch (Exception e) {
            return null;
        }
    }

    /** AES-CBC encrypt + PKCS7 pad */
    public byte[] encryptPacket(byte[] data) {
        return encryptPacket(data, currentKey, currentIv);
    }

    public static byte[] encryptPacket(byte[] data, byte[] key, byte[] iv) {
        try {
            int pad = 16 - (data.length % 16);
            byte[] padded = Arrays.copyOf(data, data.length + pad);
            Arrays.fill(padded, data.length, padded.length, (byte) pad);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(key, "AES"),
                        new IvParameterSpec(iv));
            return cipher.doFinal(padded);
        } catch (Exception e) {
            return null;
        }
    }

    /** Try to extract KEY/IV from MajorLogin response (fields 22 & 23). */
    public boolean tryExtractKeyIv(byte[] responseBody) {
        // scan offsets like x.py
        int[] testOffsets = {64, 41, 40, 0, 32, 48, 56, 72, 80, 100, 128, 160};
        for (int offset : testOffsets) {
            if (offset >= responseBody.length) continue;
            byte[] slice = Arrays.copyOfRange(responseBody, offset, responseBody.length);
            byte[][] kiv = extractKivFromProto(slice);
            if (kiv != null) {
                currentKey = kiv[0];
                currentIv  = kiv[1];
                return true;
            }
        }
        // brute scan
        for (int offset = 1; offset < Math.min(256, responseBody.length); offset++) {
            byte[] slice = Arrays.copyOfRange(responseBody, offset, responseBody.length);
            byte[][] kiv = extractKivFromProto(slice);
            if (kiv != null) {
                currentKey = kiv[0];
                currentIv  = kiv[1];
                return true;
            }
        }
        return false;
    }

    private static byte[][] extractKivFromProto(byte[] data) {
        byte[] key = null, iv = null;
        int offset = 0;
        while (offset < data.length) {
            long[] hdr = decodeVarint(data, offset);
            if (hdr == null) break;
            offset = (int) hdr[1];
            int fieldNum  = (int)(hdr[0] >> 3);
            int wireType  = (int)(hdr[0] & 0x7);
            if (wireType == 0) {
                long[] val = decodeVarint(data, offset);
                if (val == null) break;
                offset = (int) val[1];
            } else if (wireType == 2) {
                long[] len = decodeVarint(data, offset);
                if (len == null) break;
                offset = (int) len[1];
                int length = (int) len[0];
                if (offset + length > data.length) break;
                byte[] val = Arrays.copyOfRange(data, offset, offset + length);
                offset += length;
                // fields 22 and 23 are KEY and IV hex strings
                if (fieldNum == 22 || fieldNum == 23) {
                    try {
                        String hex = new String(val).trim();
                        if (hex.length() >= 32 && isHex(hex)) {
                            byte[] bytes = hexToBytes(hex.substring(0, 32));
                            if (fieldNum == 22) key = bytes;
                            else                iv  = bytes;
                        }
                    } catch (Exception ignored) {}
                }
            } else { break; }
        }
        if (key != null && iv != null) return new byte[][]{key, iv};
        return null;
    }

    static long[] decodeVarint(byte[] data, int offset) {
        long result = 0; int shift = 0;
        while (offset < data.length) {
            int b = data[offset++] & 0xFF;
            result |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return new long[]{result, offset};
            shift += 7;
            if (shift >= 64) return null;
        }
        return null;
    }

    private static boolean isHex(String s) {
        for (char c : s.toCharArray()) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte)((Character.digit(hex.charAt(i), 16) << 4)
                               + Character.digit(hex.charAt(i+1), 16));
        }
        return out;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
