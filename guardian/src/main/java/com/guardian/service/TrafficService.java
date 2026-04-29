package com.guardian.service;

import com.guardian.model.PacketData;
import com.guardian.model.PacketRecord;
import com.guardian.repository.PacketRepository;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

import java.time.LocalTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * =====================================================
 * FILE: TrafficService.java  ← UPDATED
 *
 * Changes from your original file:
 * 1. Added @Autowired PacketRepository (database)
 * 2. Added Smart Scoring System
 * 3. Added saveToDatabase() method
 * 4. Added getHistory(), getSuspiciousHistory(), getStats()
 * 5. Added DB size control (max 10,000 records)
 * 6. Added IP reset thread (every 60s)
 *
 * Your original logic is kept exactly the same!
 * =====================================================
 */
@Service
public class TrafficService {

    // ✅ NEW: Database connection
    @Autowired
    private PacketRepository packetRepository;

    // Your original variables (unchanged)
    private final Map<String, Integer> requestCount  = new HashMap<>();
    private final Map<String, Long>    firstSeenTime = new HashMap<>();
    private final List<PacketData>     recentPackets = new CopyOnWriteArrayList<>();

    // ✅ NEW: For scoring system
    private final Map<String, Integer> ipPacketCount = new ConcurrentHashMap<>();
    private final Set<String>          seenIps       = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final List<Map<String, Object>> scoreHistory = new CopyOnWriteArrayList<>();

    // Your original variables (unchanged)
    private PcapNetworkInterface networkInterface;
    private PcapHandle           handle;
    private Thread               captureThread;
    private volatile boolean     isCapturing = false;
    private static final int     WINDOW_SECONDS = 10;

    // ✅ NEW: Cleanup thread reference
    private Thread cleanupThread;

    // =====================================================
    // SAFE IP LIST (for scoring)
    // These IPs will NOT be flagged as suspicious
    // =====================================================
    private static final List<String> SAFE_PREFIXES = Arrays.asList(
        "192.168.", "10.", "172.16.", "172.17.", "127.", "0.", "255.",
        "142.250.", "142.251.", "172.217.", "216.58.", "74.125.",   // Google
        "8.8.",    "8.4.",                                          // Google DNS
        "151.101.",                                                  // Fastly
        "104.16.", "104.17.", "1.1.1.", "103.",                    // Cloudflare
        "13.",     "18.",     "52.",    "54.",   "98.", "99.",      // Amazon AWS
        "20.",     "40.",                                           // Microsoft
        "34.",     "35.",                                           // Google Cloud
        "31.13.",  "157.240.", "179.60.",                          // Meta/Facebook
        "104.",    "23."                                            // Akamai/CDN
    );

    // =====================================================
    // SCORING SYSTEM
    // =====================================================

    /**
     * Is this IP from an unknown/suspicious source?
     */
    private boolean isSuspiciousIp(String ip) {
        if (ip == null) return false;
        for (String prefix : SAFE_PREFIXES) {
            if (ip.startsWith(prefix)) return false; // Known safe!
        }
        return true; // Not in safe list = suspicious
    }

    /**
     * Is it nighttime? (12AM - 6AM)
     * Traffic at night when you're not using PC = suspicious!
     */
    private boolean isNightTime() {
        LocalTime now = LocalTime.now();
        return now.isAfter(LocalTime.of(0, 0)) &&
               now.isBefore(LocalTime.of(6, 0));
    }

    /**
     * =====================================================
     * SCORING FUNCTION - decides importance of each packet
     *
     * Rules:
     *   +3 = Unknown IP (not in safe list)
     *   +2 = Night time traffic (12AM - 6AM)
     *   +2 = Large packet (size > 5000 bytes)
     *   +3 = High frequency (same IP sent 100+ packets/min)
     *   +1 = First time seeing this IP (new connection)
     *
     * Score meaning:
     *   0-1 = NORMAL   → skip (don't save to DB)
     *   2-3 = WARNING  → save to DB
     *   4+  = CRITICAL → save to DB + print alert
     * =====================================================
     */
    private int[] scorePacket(String src, String dst, int size,
                               List<String> reasons) {
        int score = 0;

        // Rule 1: Unknown IP? +3
        boolean srcSus = isSuspiciousIp(src);
        boolean dstSus = isSuspiciousIp(dst);
        if (srcSus) { score += 3; reasons.add("Unknown source IP: " + src + " (+3)"); }
        if (dstSus) { score += 3; reasons.add("Unknown dest IP: "   + dst + " (+3)"); }

        // Rule 2: Night time? +2
        if (isNightTime()) {
            score += 2;
            reasons.add("Night time traffic 12AM-6AM (+2)");
        }

        // Rule 3: Large packet? +2
        if (size > 5000) {
            score += 2;
            reasons.add("Large packet " + size + " bytes (+2)");
        }

        // Rule 4: High frequency? +3
        int srcCount = ipPacketCount.getOrDefault(src, 0);
        int dstCount = ipPacketCount.getOrDefault(dst, 0);
        if (srcCount > 100) { score += 3; reasons.add("High freq from " + src + ": " + srcCount + "/min (+3)"); }
        if (dstCount > 100) { score += 3; reasons.add("High freq to "   + dst + ": " + dstCount + "/min (+3)"); }

        // Rule 5: First time seeing this suspicious IP? +1
        if (!seenIps.contains(src) && srcSus) { score += 1; reasons.add("New IP: " + src + " (+1)"); }
        if (!seenIps.contains(dst) && dstSus) { score += 1; reasons.add("New IP: " + dst + " (+1)"); }

        // Update tracking maps
        seenIps.add(src);
        seenIps.add(dst);
        ipPacketCount.merge(src, 1, Integer::sum);
        ipPacketCount.merge(dst, 1, Integer::sum);

        // Return [score, isSuspicious(0 or 1)]
        return new int[]{score, (srcSus || dstSus) ? 1 : 0};
    }

    // =====================================================
    // YOUR ORIGINAL startCapture() - with small additions
    // =====================================================
    @PostConstruct
    public void startCapture() {

        // ✅ NEW: Start IP count reset thread
        startCleanupThread();

        // ✅ NEW: Show DB stats on startup
        try {
            long total = packetRepository.countAllPackets();
            long sus   = packetRepository.countBySuspiciousTrue();
            System.out.println("Database loaded: " + total + " total, " + sus + " suspicious packets");
        } catch (Exception e) {
            System.out.println("Database initializing for first time...");
        }

        try {
            List<PcapNetworkInterface> allDevices = Pcaps.findAllDevs();

            if (allDevices == null || allDevices.isEmpty()) {
                System.out.println("No network interfaces found!");
                startDemoMode(); // ✅ FIXED: now calls demo mode
                return;
            }

            networkInterface = allDevices.get(4); // Your MediaTek WiFi
            System.out.println("Using network interface: " + networkInterface.getName());

            handle = networkInterface.openLive(
                65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                10
            );

            isCapturing = true;
            captureThread = new Thread(this::captureLoop, "PacketCaptureThread");
            captureThread.setDaemon(true);
            captureThread.start();

            System.out.println("Packet capture started! Guardian is watching your network.");
            System.out.println("Smart Scoring: ACTIVE | Database: ACTIVE");

        } catch (PcapNativeException e) {
            System.out.println("Could not start packet capture: " + e.getMessage());
            startDemoMode();
        }
    }

    // =====================================================
    // YOUR ORIGINAL captureLoop() - unchanged
    // =====================================================
    private void captureLoop() {
        System.out.println("Capture loop started...");

        while (isCapturing) {
            try {
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    processPacket(packet);
                }
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // skip bad packets
            }
        }

        System.out.println("Capture loop stopped.");
    }

    // =====================================================
    // YOUR ORIGINAL processPacket() - with DB saving added
    // =====================================================
    private void processPacket(Packet packet) {
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);

        if (ipV4Packet != null) {
            String sourceIp      = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            String destinationIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();
            int    packetSize    = packet.length();

            // ---- YOUR ORIGINAL LOGIC (unchanged) ----
            requestCount.merge(sourceIp, 1, Integer::sum);
            long now = System.currentTimeMillis();
            firstSeenTime.putIfAbsent(sourceIp, now);
            requestCount.merge(sourceIp, 1, Integer::sum);
            long duration = now - firstSeenTime.get(sourceIp);

            if (duration <= 10000 && requestCount.get(sourceIp) > 50) {
                System.out.println("Suspicious IP (high rate): " + sourceIp);
            }

            if (duration > 10000) {
                requestCount.put(sourceIp, 1);
                firstSeenTime.put(sourceIp, now);
            }
            // ---- END OF YOUR ORIGINAL LOGIC ----

            // Always add to RAM for live chart
            PacketData data = new PacketData(sourceIp, destinationIp, packetSize);
            recentPackets.add(data);
            removeOldPackets();

            // ✅ NEW: Score this packet and save to DB if important
            List<String> reasons = new ArrayList<>();
            int[] scoreResult = scorePacket(sourceIp, destinationIp, packetSize, reasons);
            int     score      = scoreResult[0];
            boolean suspicious = scoreResult[1] == 1;

            String level = score >= 4 ? "CRITICAL" : score >= 2 ? "WARNING" : "NORMAL";

            if (level.equals("CRITICAL")) {
                // Save to DB + Print alert
                saveToDatabase(sourceIp, destinationIp, packetSize, suspicious, score, reasons);
                addToScoreHistory(sourceIp, destinationIp, packetSize, score, level, reasons);
                System.out.println("\n🚨 CRITICAL! Score:" + score + " | " + sourceIp + " → " + destinationIp);
                for (String r : reasons) System.out.println("   → " + r);

            } else if (level.equals("WARNING")) {
                // Save to DB (no console alert for warning)
                saveToDatabase(sourceIp, destinationIp, packetSize, suspicious, score, reasons);
                addToScoreHistory(sourceIp, destinationIp, packetSize, score, level, reasons);
            }
            // NORMAL → don't save to DB (keeps DB small!)
        }
    }

    // =====================================================
    // ✅ NEW: Save to Database
    // =====================================================
    private void saveToDatabase(String src, String dst, int size,
                                 boolean suspicious, int score,
                                 List<String> reasons) {
        try {
            String reasonStr = String.join(" | ", reasons);
            PacketRecord record = new PacketRecord(src, dst, size, suspicious, score, reasonStr);
            packetRepository.save(record);

            // ✅ DB SIZE CONTROL: Keep max 10,000 records
            long count = packetRepository.countAllPackets();
            if (count > 10000) {
                // Delete oldest 500 records
                List<PacketRecord> oldest = packetRepository.findAllOrderByOldest();
                int toDelete = Math.min(500, oldest.size());
                for (int i = 0; i < toDelete; i++) {
                    packetRepository.delete(oldest.get(i));
                }
                System.out.println("DB cleanup: deleted " + toDelete + " old records");
            }

        } catch (Exception e) {
            System.err.println("DB save error: " + e.getMessage());
        }
    }

    // ✅ NEW: Add to score history list (for /scores API)
    private void addToScoreHistory(String src, String dst, int size,
                                    int score, String level,
                                    List<String> reasons) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("time",        java.time.LocalDateTime.now()
                                     .toString().replace("T"," ").substring(0,19));
        entry.put("source",      src);
        entry.put("destination", dst);
        entry.put("size",        size + " bytes");
        entry.put("score",       score);
        entry.put("level",       level);
        entry.put("reasons",     reasons);

        scoreHistory.add(0, entry);
        if (scoreHistory.size() > 50) scoreHistory.remove(scoreHistory.size() - 1);
    }

    // ✅ NEW: Reset IP counts every 60 seconds
    private void startCleanupThread() {
        cleanupThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(60_000); // 60 seconds
                    ipPacketCount.clear();
                    System.out.println("IP packet counts reset (60s cycle)");
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "CleanupThread");
        cleanupThread.setDaemon(true);
        cleanupThread.start();
    }

    // =====================================================
    // YOUR ORIGINAL METHODS (unchanged)
    // =====================================================
    private void removeOldPackets() {
        long cutoffTime = System.currentTimeMillis() - (WINDOW_SECONDS * 1000L);
        recentPackets.removeIf(packet -> packet.getTimestamp() < cutoffTime);
    }

    public List<Integer> getPacketsPerSecond() {
        long now = System.currentTimeMillis();
        int[] counts = new int[WINDOW_SECONDS];
        List<PacketData> snapshot = new ArrayList<>(recentPackets);

        for (PacketData packet : snapshot) {
            long ageMs = now - packet.getTimestamp();
            int secondsAgo = (int)(ageMs / 1000);
            if (secondsAgo >= 0 && secondsAgo < WINDOW_SECONDS) {
                counts[secondsAgo]++;
            }
        }

        List<Integer> result = new ArrayList<>();
        for (int i = WINDOW_SECONDS - 1; i >= 0; i--) {
            result.add(counts[i]);
        }
        return result;
    }

    public List<Map<String, Object>> getRecentConnections() {
        List<PacketData> snapshot = new ArrayList<>(recentPackets);
        int startIndex = Math.max(0, snapshot.size() - 20);
        List<PacketData> recent = snapshot.subList(startIndex, snapshot.size());

        List<Map<String, Object>> result = new ArrayList<>();
        for (int i = recent.size() - 1; i >= 0; i--) {
            PacketData p = recent.get(i);
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("source",      p.getSourceIp());
            entry.put("destination", p.getDestinationIp());
            entry.put("size",        p.getPacketSize() + " bytes");
            entry.put("time",        new Date(p.getTimestamp()).toString());
            result.add(entry);
        }
        return result;
    }

    public int getTotalPacketCount() { return recentPackets.size(); }

    // =====================================================
    // ✅ NEW: Database API methods
    // =====================================================

    /** Last 50 packets from DB (history) */
    public List<Map<String, Object>> getHistory() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (PacketRecord r : packetRepository.findTop50ByOrderByCapturedAtDesc()) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("id",          r.getId());
            e.put("time",        r.getFormattedTime());
            e.put("source",      r.getSourceIp());
            e.put("destination", r.getDestinationIp());
            e.put("size",        r.getPacketSize() + " bytes");
            e.put("suspicious",  r.isSuspicious());
            e.put("score",       r.getThreatScore());
            e.put("reason",      r.getReason());
            result.add(e);
        }
        return result;
    }

    /** All suspicious packets from DB */
    public List<Map<String, Object>> getSuspiciousHistory() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (PacketRecord r : packetRepository.findTop100BySuspiciousTrueOrderByCapturedAtDesc()) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("id",          r.getId());
            e.put("time",        r.getFormattedTime());
            e.put("source",      r.getSourceIp());
            e.put("destination", r.getDestinationIp());
            e.put("size",        r.getPacketSize() + " bytes");
            e.put("score",       r.getThreatScore());
            e.put("reason",      r.getReason());
            result.add(e);
        }
        return result;
    }

    /** Score history (last 50 scored packets) */
    public List<Map<String, Object>> getScoreHistory() {
        return new ArrayList<>(scoreHistory);
    }

    /** DB statistics */
    public Map<String, Object> getDatabaseStats() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalPacketsInDB",  packetRepository.countAllPackets());
        stats.put("suspiciousPackets", packetRepository.countBySuspiciousTrue());
        stats.put("uniqueIpsSeen",     seenIps.size());
        stats.put("scoredPackets",     scoreHistory.size());

        // Top 5 destinations
        List<Object[]> top = packetRepository.findTopDestinations();
        List<Map<String, Object>> topList = new ArrayList<>();
        for (int i = 0; i < Math.min(5, top.size()); i++) {
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("ip",    top.get(i)[0]);
            d.put("count", top.get(i)[1]);
            topList.add(d);
        }
        stats.put("topDestinations", topList);
        return stats;
    }

    // =====================================================
    // YOUR ORIGINAL DEMO MODE (with DB saving added)
    // =====================================================
    private void startDemoMode() {
        System.out.println("Starting DEMO MODE - generating simulated network traffic");

        String[] sampleSources = {"192.168.1.101","192.168.1.102","10.0.0.5","172.16.0.10"};
        String[] sampleDests   = {
            "142.250.80.46","151.101.1.140","13.107.42.14","52.96.0.1",
            "104.16.133.229","8.8.8.8",
            "119.8.160.175","185.220.101.5" // These are suspicious
        };

        isCapturing = true;
        captureThread = new Thread(() -> {
            Random random = new Random();
            while (isCapturing) {
                try {
                    int n = random.nextInt(8) + 1;
                    for (int i = 0; i < n; i++) {
                        String src  = sampleSources[random.nextInt(sampleSources.length)];
                        String dst  = sampleDests[random.nextInt(sampleDests.length)];
                        int    size = 64 + random.nextInt(5000);

                        recentPackets.add(new PacketData(src, dst, size));

                        List<String> reasons = new ArrayList<>();
                        int[] sr = scorePacket(src, dst, size, reasons);
                        int score = sr[0];
                        boolean sus = sr[1] == 1;
                        String level = score >= 4 ? "CRITICAL" : score >= 2 ? "WARNING" : "NORMAL";

                        if (score >= 2) {
                            saveToDatabase(src, dst, size, sus, score, reasons);
                            addToScoreHistory(src, dst, size, score, level, reasons);
                        }
                    }
                    removeOldPackets();
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }, "DemoModeThread");

        captureThread.setDaemon(true);
        captureThread.start();
    }

    // =====================================================
    // YOUR ORIGINAL stopCapture()
    // =====================================================
    @PreDestroy
    public void stopCapture() {
        isCapturing = false;
        if (captureThread != null) captureThread.interrupt();
        if (cleanupThread != null) cleanupThread.interrupt();
        if (handle != null && handle.isOpen()) handle.close();
        System.out.println("Guardian stopped. All data saved to guardian.db");
    }
}
