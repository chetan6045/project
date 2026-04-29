package com.guardian.controller;

import com.guardian.service.TrafficService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * =====================================================
 * FILE: TrafficController.java  ← UPDATED
 *
 * Your original APIs (unchanged):
 *   GET /traffic     → live chart data
 *   GET /connections → live table data
 *   GET /status      → health check
 *
 * ✅ NEW APIs added:
 *   GET /history         → last 50 packets from DB
 *   GET /threats/history → all suspicious packets from DB
 *   GET /scores          → scored packets with reasons
 *   GET /stats           → DB stats + top destinations
 * =====================================================
 */
@RestController
@CrossOrigin(origins = "*")
public class TrafficController {

    @Autowired
    private TrafficService trafficService;

    // =====================================================
    // YOUR ORIGINAL APIs (unchanged)
    // =====================================================

    @GetMapping("/traffic")
    public Map<String, Object> getTrafficData() {
        List<Integer> packetsPerSecond = trafficService.getPacketsPerSecond();
        Map<String, Object> response = new HashMap<>();
        response.put("packetsPerSecond", packetsPerSecond);
        response.put("totalPackets", trafficService.getTotalPacketCount());
        String[] labels = new String[10];
        for (int i = 0; i < 10; i++) labels[i] = "-" + (10 - i) + "s";
        response.put("labels", labels);
        return response;
    }

    @GetMapping("/connections")
    public List<Map<String, Object>> getConnections() {
        return trafficService.getRecentConnections();
    }

    @GetMapping("/status")
    public Map<String, String> getStatus() {
        Map<String, String> status = new HashMap<>();
        status.put("status",  "online");
        status.put("app",     "Guardian Network Analyzer");
        status.put("version", "2.0.0 - Database + Scoring Active");
        return status;
    }

    // =====================================================
    // ✅ NEW: Database APIs
    // =====================================================

    /**
     * GET /history
     * Last 50 important packets from database.
     * Data survives even after app restart!
     *
     * Example response:
     * [
     *   {
     *     "id": 42,
     *     "time": "2025-04-19 23:42:37",
     *     "source": "192.168.1.5",
     *     "destination": "185.220.101.5",
     *     "size": "1200 bytes",
     *     "suspicious": true,
     *     "score": 6,
     *     "reason": "Unknown dest IP (+3) | Night time (+2) | New IP (+1)"
     *   }
     * ]
     */
    @GetMapping("/history")
    public List<Map<String, Object>> getHistory() {
        return trafficService.getHistory();
    }

    /**
     * GET /threats/history
     * All suspicious packets ever detected.
     * Great for security audit!
     */
    @GetMapping("/threats/history")
    public List<Map<String, Object>> getThreatHistory() {
        return trafficService.getSuspiciousHistory();
    }

    /**
     * GET /scores
     * Last 50 packets that got a score (WARNING or CRITICAL).
     * Shows exactly WHY each packet was flagged.
     *
     * Example response:
     * [
     *   {
     *     "time": "2025-04-19 23:42:37",
     *     "source": "192.168.1.5",
     *     "destination": "185.220.101.5",
     *     "score": 6,
     *     "level": "CRITICAL",
     *     "reasons": [
     *       "Unknown dest IP: 185.220.101.5 (+3)",
     *       "Night time traffic 12AM-6AM (+2)",
     *       "New IP: 185.220.101.5 (+1)"
     *     ]
     *   }
     * ]
     */
    @GetMapping("/scores")
    public List<Map<String, Object>> getScores() {
        return trafficService.getScoreHistory();
    }

    /**
     * GET /stats
     * Database statistics overview.
     *
     * Example response:
     * {
     *   "totalPacketsInDB": 1532,
     *   "suspiciousPackets": 23,
     *   "uniqueIpsSeen": 48,
     *   "topDestinations": [
     *     {"ip": "8.8.8.8",         "count": 523},
     *     {"ip": "142.250.80.46",   "count": 312}
     *   ]
     * }
     */
    @GetMapping("/stats")
    public Map<String, Object> getStats() {
        return trafficService.getDatabaseStats();
    }
}
