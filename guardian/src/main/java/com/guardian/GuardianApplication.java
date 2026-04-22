package com.guardian;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * =====================================================
 * FILE: GuardianApplication.java
 * PURPOSE: The entry point of our entire Spring Boot app.
 *
 * When you run this class, Spring Boot:
 *   1. Starts an embedded web server (Tomcat) on port 8080
 *   2. Scans for @Service, @RestController, etc. classes
 *   3. Wires everything together automatically
 *   4. Calls our @PostConstruct methods (starts packet capture)
 *
 * @SpringBootApplication is a magic annotation that enables:
 *   - Auto-configuration
 *   - Component scanning
 *   - Configuration support
 * =====================================================
 */
@SpringBootApplication
public class GuardianApplication {

    public static void main(String[] args) {

        // Print a nice welcome banner
        System.out.println("╔══════════════════════════════════════════╗");
        System.out.println("║       GUARDIAN - Network Analyzer        ║");
        System.out.println("║           Starting up...                 ║");
        System.out.println("╚══════════════════════════════════════════╝");
        System.out.println();
        System.out.println("📌 Dashboard will be available at:");
        System.out.println("   http://localhost:8080");
        System.out.println();

        // This single line starts the entire Spring Boot application!
        SpringApplication.run(GuardianApplication.class, args);
    }
}
