package com.guardian.service;

import com.guardian.model.PacketData;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class TrafficService {
   private final Map<String, Integer> requestCount = new HashMap<>();
    private final Map<String, Long> firstSeenTime = new HashMap<>();
    private final List<PacketData> recentPackets = new CopyOnWriteArrayList<>();

    private PcapNetworkInterface networkInterface;
    private PcapHandle handle;
    private Thread captureThread;
    private volatile boolean isCapturing = false;

    private static final int WINDOW_SECONDS = 10;

    @PostConstruct
    public void startCapture() {
        try {
            List<PcapNetworkInterface> allDevices = Pcaps.findAllDevs();

            if (allDevices == null || allDevices.isEmpty()) {
                System.out.println("No network interfaces found! ");
                
                return;
            }

            networkInterface = allDevices.get(4); 
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

        } catch (PcapNativeException e) {
            System.out.println("Could not start packet capture: " + e.getMessage());
            
        }
    }

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
               
            }
        }

        System.out.println("Capture loop stopped.");
    }

    private void processPacket(Packet packet) {
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);

        if (ipV4Packet != null) {
            String sourceIp      = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            String destinationIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();
            int    packetSize    = packet.length();
            
          
           requestCount.merge(sourceIp, 1, Integer::sum);

           long now = System.currentTimeMillis();


firstSeenTime.putIfAbsent(sourceIp, now);


requestCount.merge(sourceIp, 1, Integer::sum);


long duration = now - firstSeenTime.get(sourceIp);


if (duration <= 10000 && requestCount.get(sourceIp) > 50) {
    System.out.println("🚨 Suspicious IP (high rate): " + sourceIp);
}


if (duration > 10000) {
    requestCount.put(sourceIp, 1);
    firstSeenTime.put(sourceIp, now);
}

           PacketData data = new PacketData(sourceIp, destinationIp, packetSize);
           recentPackets.add(data);
           removeOldPackets();
        }
    }

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

    public int getTotalPacketCount() {
        return recentPackets.size();
    }

    private PcapNetworkInterface pickBestInterface(List<PcapNetworkInterface> devices) {
        System.out.println("Available network interfaces:");
        for (int i = 0; i < devices.size(); i++) {
            System.out.println("  [" + i + "] " + devices.get(i).getName()
                    + " - " + devices.get(i).getDescription());
        }

        for (PcapNetworkInterface dev : devices) {
            if (!dev.isLoopBack() && !dev.getAddresses().isEmpty()) {
                return dev;
            }
        }
        return devices.get(0);
    }

    private void startDemoMode() {
        System.out.println("Starting DEMO MODE - generating simulated network traffic");

        String[] sampleSources      = {"192.168.1.101", "192.168.1.102", "10.0.0.5", "172.16.0.10"};
        String[] sampleDestinations = {"142.250.80.46", "151.101.1.140", "13.107.42.14",
                                       "52.96.0.1", "104.16.133.229", "8.8.8.8"};

        isCapturing = true;
        captureThread = new Thread(() -> {
            Random random = new Random();
            while (isCapturing) {
                try {
                    int packetsThisSecond = random.nextInt(8) + 1;
                    for (int i = 0; i < packetsThisSecond; i++) {
                        String src  = sampleSources[random.nextInt(sampleSources.length)];
                        String dst  = sampleDestinations[random.nextInt(sampleDestinations.length)];
                        int    size = 64 + random.nextInt(1400);
                        recentPackets.add(new PacketData(src, dst, size));
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

    @PreDestroy
    public void stopCapture() {
        isCapturing = false;
        if (captureThread != null) captureThread.interrupt();
        if (handle != null && handle.isOpen()) handle.close();
        System.out.println("Guardian stopped.");
    }
}
