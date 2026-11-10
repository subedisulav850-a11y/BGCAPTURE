package com.bashant.capture.ui;

import android.graphics.Color;
import android.view.*;
import android.widget.*;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.bashant.capture.proxy.CapturedPacket;

import java.util.*;

public class PacketAdapter extends RecyclerView.Adapter<PacketAdapter.VH> {

    public interface OnPacketClick {
        void onResend(CapturedPacket pkt);
        void onDetail(CapturedPacket pkt);
    }

    private final List<CapturedPacket> items = new ArrayList<>();
    private final OnPacketClick listener;

    // filter state
    private boolean showTcp = true;
    private boolean showUdp = true;
    private final List<CapturedPacket> filtered = new ArrayList<>();

    public PacketAdapter(OnPacketClick listener) {
        this.listener = listener;
    }

    public void setFilter(boolean tcp, boolean udp) {
        showTcp = tcp; showUdp = udp;
        rebuildFiltered();
    }

    public void addPacket(CapturedPacket pkt) {
        items.add(0, pkt);
        if (items.size() > 1000) items.remove(items.size() - 1);
        rebuildFiltered();
    }

    public void clear() {
        items.clear();
        rebuildFiltered();
    }

    private void rebuildFiltered() {
        filtered.clear();
        for (CapturedPacket p : items) {
            if (p.protocol == CapturedPacket.Protocol.TCP && !showTcp) continue;
            if (p.protocol == CapturedPacket.Protocol.UDP && !showUdp) continue;
            filtered.add(p);
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LinearLayout root = new LinearLayout(parent.getContext());
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(16, 10, 16, 10);
        root.setLayoutParams(new RecyclerView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return new VH(root);
    }

    @Override
    public void onBindViewHolder(@NonNull VH h, int pos) {
        CapturedPacket pkt = filtered.get(pos);
        boolean isC2S = pkt.direction == CapturedPacket.Direction.CLIENT_TO_SERVER;
        boolean isUdp = pkt.protocol == CapturedPacket.Protocol.UDP;

        h.root.setBackgroundColor(Color.parseColor(isUdp ? "#1A1210" : "#0D1117"));

        // border-left simulation via left padding color
        int accentColor = isUdp
                ? Color.parseColor("#FB923C")   // orange = UDP
                : (isC2S
                        ? Color.parseColor("#4ADE80")  // green = C→S
                        : Color.parseColor("#22D3EE")); // cyan  = S→C

        // Meta line
        String proto = pkt.protocol.name();
        String dir   = isC2S ? "▲ C→S" : "▼ S→C";
        String meta  = pkt.getTimestampStr() + "  " + proto + "  " + dir
                     + "  " + (pkt.rawData != null ? pkt.rawData.length : 0) + "B"
                     + (pkt.label != null && !pkt.label.isEmpty() ? "  [" + pkt.label + "]" : "");
        h.meta.setText(meta);
        h.meta.setTextColor(Color.parseColor("#8B98A8"));

        // Hex preview (collapsed)
        String hex = pkt.rawData != null ? bytesToHexPreview(pkt.rawData, 32) : "(empty)";
        h.hex.setText(hex);
        h.hex.setTextColor(accentColor);

        // Buttons
        h.btnResend.setOnClickListener(v -> listener.onResend(pkt));
        h.btnDetail.setOnClickListener(v -> listener.onDetail(pkt));
    }

    @Override
    public int getItemCount() { return filtered.size(); }

    private static String bytesToHexPreview(byte[] data, int maxBytes) {
        int n = Math.min(data.length, maxBytes);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(String.format("%02X ", data[i]));
        if (data.length > maxBytes) sb.append("…");
        return sb.toString().trim();
    }

    static class VH extends RecyclerView.ViewHolder {
        final LinearLayout root;
        final TextView meta, hex;
        final Button btnResend, btnDetail;

        VH(LinearLayout root) {
            super(root);
            this.root = root;

            meta = new TextView(root.getContext());
            meta.setTextSize(10f);
            meta.setPadding(0, 0, 0, 4);

            hex = new TextView(root.getContext());
            hex.setTextSize(9f);
            hex.setTypeface(android.graphics.Typeface.MONOSPACE);
            hex.setMaxLines(2);
            hex.setEllipsize(android.text.TextUtils.TruncateAt.END);
            hex.setPadding(0, 0, 0, 6);

            LinearLayout btnRow = new LinearLayout(root.getContext());
            btnRow.setOrientation(LinearLayout.HORIZONTAL);
            btnRow.setGravity(android.view.Gravity.CENTER_VERTICAL);

            btnResend = new Button(root.getContext());
            btnResend.setText("↻ RESEND");
            btnResend.setTextSize(9f);
            btnResend.setTextColor(Color.parseColor("#4ADE80"));
            btnResend.setBackgroundColor(Color.parseColor("#1A2A1A"));
            btnResend.setPadding(14, 4, 14, 4);
            LinearLayout.LayoutParams lp1 = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            lp1.setMarginEnd(8);
            btnResend.setLayoutParams(lp1);

            btnDetail = new Button(root.getContext());
            btnDetail.setText("⬡ DETAIL");
            btnDetail.setTextSize(9f);
            btnDetail.setTextColor(Color.parseColor("#22D3EE"));
            btnDetail.setBackgroundColor(Color.parseColor("#0A1E25"));
            btnDetail.setPadding(14, 4, 14, 4);

            btnRow.addView(btnResend);
            btnRow.addView(btnDetail);
            root.addView(meta);
            root.addView(hex);
            root.addView(btnRow);
        }
    }
}
