package com.bashant.capture.proxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

public class PacketStore {

    public interface Listener {
        void onPacketAdded(CapturedPacket pkt);
    }

    private static final int MAX_PACKETS = 1000;

    private final LinkedList<CapturedPacket>  ring     = new LinkedList<>();
    private final AtomicLong                  counter  = new AtomicLong(0);
    private final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();

    private static final PacketStore INSTANCE = new PacketStore();
    public static PacketStore get() { return INSTANCE; }

    private PacketStore() {}

    public long nextId() { return counter.incrementAndGet(); }

    public synchronized void add(CapturedPacket pkt) {
        ring.addFirst(pkt);
        if (ring.size() > MAX_PACKETS) ring.removeLast();
        for (Listener l : listeners) {
            try { l.onPacketAdded(pkt); } catch (Exception ignored) {}
        }
    }

    public synchronized List<CapturedPacket> snapshot() {
        return new ArrayList<>(ring);
    }

    public synchronized void clear() { ring.clear(); }

    public void addListener(Listener l) { listeners.add(l); }
    public void removeListener(Listener l) { listeners.remove(l); }
}
