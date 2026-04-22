package com.guardian.controller;

import com.guardian.service.TrafficService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * =====================================================
 * FILE: TrafficController.java
 * PURPOSE: Defines the REST API endpoints.
 *
 * A REST API is like a menu at a restaurant:
 *   - The browser (client) orders something
 *   - The controller takes the order
 *   - It asks the Service (kitchen) to prepare it
 *   - Then sends back the result as JSON
 *
 * @RestController = This class handles HTTP requests
 * @CrossOrigin    = Allows the frontend to call these APIs
 *                  (needed when HTML and Java run separately)
 * =====================================================
 */
@RestController
@CrossOrigin(origins = "*") // Allow requests from any origin (important for development)
public class TrafficController {

    // Spring Boot automatically injects (provides) our TrafficService here.
    // We don't need to write "new TrafficService()" — Spring handles it!
    @Autowired
    private TrafficService trafficService;

    /**
     * ===== API 1: GET /traffic =====
     *
     * Returns how many packets were captured per second over the last 10 seconds.
     *
     * Example response:
     * {
     *   "packetsPerSecond": [3, 7, 12, 5, 8, 20, 4, 11, 6, 9],
     *   "totalPackets": 85,
     *   "labels": ["-10s", "-9s", "-8s", "-7s", "-6s", "-5s", "-4s", "-3s", "-2s", "-1s"]
     * }
     *
     * The frontend uses this data to draw the bar chart.
     */
    @GetMapping("/traffic")
    public Map<String, Object> getTrafficData() {

        // Ask the service for packets-per-second data
        List<Integer> packetsPerSecond = trafficService.getPacketsPerSecond();

        // Build the response object (this becomes JSON automatically)
        Map<String, Object> response = new HashMap<>();
        response.put("packetsPerSecond", packetsPerSecond);
        response.put("totalPackets", trafficService.getTotalPacketCount());

        // Create time labels for the X-axis of our chart
        // These will show "-10s", "-9s", ... "-1s"
        String[] labels = new String[10];
        for (int i = 0; i < 10; i++) {
            labels[i] = "-" + (10 - i) + "s";
        }
        response.put("labels", labels);

        return response;
    }

    /**
     * ===== API 2: GET /connections =====
     *
     * Returns the most recent source→destination IP connections.
     *
     * Example response:
     * [
     *   {
     *     "source": "192.168.1.5",
     *     "destination": "142.250.80.46",
     *     "size": "512 bytes",
     *     "time": "Tue Apr 01 12:34:56 IST 2025"
     *   },
     *   ...
     * ]
     *
     * The frontend uses this to fill the connections table.
     */
    @GetMapping("/connections")
    public List<Map<String, Object>> getConnections() {
        return trafficService.getRecentConnections();
    }

    /**
     * ===== API 3: GET /status =====
     *
     * A simple health-check endpoint.
     * Useful to confirm the backend is running before the frontend starts.
     *
     * Example response:
     * { "status": "online", "app": "Guardian Network Analyzer" }
     */
    @GetMapping("/status")
    public Map<String, String> getStatus() {
        Map<String, String> status = new HashMap<>();
        status.put("status", "online");
        status.put("app", "Guardian Network Analyzer");
        status.put("version", "1.0.0");
        return status;
    }
}
