package com.guardian.repository;

import com.guardian.model.PacketRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * =====================================================
 * FILE: PacketRepository.java  ← NEW FILE
 * PURPOSE: All database operations live here.
 *
 * By extending JpaRepository, we get FREE methods:
 *   save()    → insert a row
 *   findAll() → get all rows
 *   count()   → count rows
 *   delete()  → delete a row
 *
 * We also write custom queries below.
 * Spring automatically writes the SQL for us!
 * =====================================================
 */
@Repository
public interface PacketRepository extends JpaRepository<PacketRecord, Long> {

    // Last 50 packets (newest first) - for /history API
    List<PacketRecord> findTop50ByOrderByCapturedAtDesc();

    // All suspicious packets (newest first) - for /threats API
    List<PacketRecord> findTop100BySuspiciousTrueOrderByCapturedAtDesc();

    // All critical packets (score >= 4)
    List<PacketRecord> findByThreatScoreGreaterThanEqualOrderByCapturedAtDesc(int minScore);

    // Count total packets in DB
    @Query("SELECT COUNT(p) FROM PacketRecord p")
    long countAllPackets();

    // Count suspicious packets
    long countBySuspiciousTrue();

    // Top 5 most visited destinations
    @Query("SELECT p.destinationIp, COUNT(p) as cnt " +
           "FROM PacketRecord p " +
           "GROUP BY p.destinationIp " +
           "ORDER BY cnt DESC")
    List<Object[]> findTopDestinations();

    // Delete oldest records when DB is too big (keeps DB clean)
    @Query("SELECT p FROM PacketRecord p ORDER BY p.capturedAt ASC")
    List<PacketRecord> findAllOrderByOldest();
}
