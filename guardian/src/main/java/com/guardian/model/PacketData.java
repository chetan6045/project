package com.guardian.model;

/**
 * =====================================================
 * FILE: PacketData.java
 * PURPOSE: A simple data container (model) that holds
 *          information about one captured network packet.
 *
 * Think of this like a "form" with fields:
 *   - Who sent the data (sourceIp)
 *   - Where it was going (destinationIp)
 *   - How big the data was (packetSize)
 *   - When it was captured (timestamp)
 * =====================================================
 */
public class PacketData {

    // The IP address of the machine that sent this packet
    // Example: "192.168.1.5"
    private String sourceIp;

    // The IP address of the machine this packet was going to
    // Example: "142.250.80.46" (could be a Google server)
    private String destinationIp;

    // How many bytes this packet contained
    // A typical web request might be 100-1500 bytes
    private int packetSize;

    // The exact time this packet was captured (milliseconds since 1970)
    // We use this to filter "last 10 seconds" of data
    private long timestamp;

    // ===== CONSTRUCTOR =====
    // This is called when we create a new PacketData object
    // Example: new PacketData("192.168.1.1", "8.8.8.8", 512)
    public PacketData(String sourceIp, String destinationIp, int packetSize) {
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.packetSize = packetSize;
        this.timestamp = System.currentTimeMillis(); // Record the current time
    }

    // ===== GETTERS =====
    // These let other classes READ the values stored in this object

    public String getSourceIp() {
        return sourceIp;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public int getPacketSize() {
        return packetSize;
    }

    public long getTimestamp() {
        return timestamp;
    }

    // ===== toString =====
    // Useful for debugging - prints a readable version of this object
    @Override
    public String toString() {
        return "PacketData{" +
                "src='" + sourceIp + '\'' +
                ", dst='" + destinationIp + '\'' +
                ", size=" + packetSize + " bytes" +
                '}';
    }
}
