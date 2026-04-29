package com.guardian.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * =====================================================
 * FILE: PacketRecord.java  ← NEW FILE
 * PURPOSE: Represents one ROW in the database table.
 *
 * @Entity = This class is a database table
 * @Table  = Table name is "packets"
 *
 * Database table will look like this:
 * ┌────┬─────────────────────┬─────────────┬───────────────┬──────┬────────────┬─────────┐
 * │ id │ captured_at         │ source_ip   │ dest_ip       │ size │ suspicious │ score   │
 * ├────┼─────────────────────┼─────────────┼───────────────┼──────┼────────────┼─────────┤
 * │  1 │ 2025-04-19 23:42:37 │ 192.168.1.5 │ 8.8.8.8       │  512 │ false      │ 0       │
 * │  2 │ 2025-04-19 23:42:39 │ 192.168.1.5 │ 185.220.101.5 │ 1200 │ true       │ 6       │
 * └────┴─────────────────────┴─────────────┴───────────────┴──────┴────────────┴─────────┘
 * =====================================================
 */
@Entity
@Table(name = "packets")
public class PacketRecord {

    // Primary key - auto increments (1, 2, 3, 4...)
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // When was this packet captured?
    @Column(name = "captured_at")
    private LocalDateTime capturedAt;

    // Source IP address
    @Column(name = "source_ip")
    private String sourceIp;

    // Destination IP address
    @Column(name = "destination_ip")
    private String destinationIp;

    // Packet size in bytes
    @Column(name = "packet_size")
    private int packetSize;

    // Is this IP suspicious?
    @Column(name = "is_suspicious")
    private boolean suspicious;

    // Threat score (0=normal, 2-3=warning, 4+=critical)
    @Column(name = "threat_score")
    private int threatScore;

    // Why was this scored? (comma separated reasons)
    @Column(name = "reason", length = 500)
    private String reason;

    // ===== CONSTRUCTORS =====

    // Required by JPA - empty constructor
    public PacketRecord() {}

    // Constructor we use when saving
    public PacketRecord(String sourceIp, String destinationIp,
                        int packetSize, boolean suspicious,
                        int threatScore, String reason) {
        this.sourceIp      = sourceIp;
        this.destinationIp = destinationIp;
        this.packetSize    = packetSize;
        this.suspicious    = suspicious;
        this.threatScore   = threatScore;
        this.reason        = reason;
        this.capturedAt    = LocalDateTime.now();
    }

    // ===== GETTERS =====
    public Long          getId()            { return id; }
    public LocalDateTime getCapturedAt()    { return capturedAt; }
    public String        getSourceIp()      { return sourceIp; }
    public String        getDestinationIp() { return destinationIp; }
    public int           getPacketSize()    { return packetSize; }
    public boolean       isSuspicious()     { return suspicious; }
    public int           getThreatScore()   { return threatScore; }
    public String        getReason()        { return reason; }

    // Nicely formatted time for API responses
    public String getFormattedTime() {
        if (capturedAt == null) return "Unknown";
        return capturedAt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
}
