# 🛡️ Guardian — Network Traffic Analyzer
### A Beginner-Friendly Java Spring Boot Project

---

## 📌 What This Project Does

Guardian is a web dashboard that captures real network packets flowing through your computer and displays them live in a browser. It shows:
- A bar chart of how many packets passed per second (last 10 seconds)
- A table of recent source → destination IP connections
- Live statistics updating every second

---

## 🗂️ Project Structure (Explained Simply)

```
guardian/
│
├── pom.xml                          ← Maven config (lists all libraries we need)
│
└── src/main/
    ├── java/com/guardian/
    │   │
    │   ├── GuardianApplication.java ← ENTRY POINT — run this to start the app
    │   │
    │   ├── model/
    │   │   └── PacketData.java      ← Data container: stores info about 1 packet
    │   │
    │   ├── service/
    │   │   └── TrafficService.java  ← Core logic: captures packets, stores data
    │   │
    │   └── controller/
    │       └── TrafficController.java ← REST APIs: /traffic, /connections, /status
    │
    └── resources/
        ├── application.properties   ← App settings (port, logging level, etc.)
        └── static/
            └── index.html           ← The entire frontend (HTML + CSS + JS in one file)
```

**Flow of data:**
```
Network Card → Pcap4j (captures packets)
           → TrafficService (stores in memory)
           → TrafficController (exposes as JSON via REST API)
           → index.html (fetches JSON, updates chart every second)
```

---

## 🔧 Prerequisites — What You Need to Install

### 1. Java 17 or higher
Check if you have it:
```bash
java -version
```
If not installed, download from: https://adoptium.net/

### 2. Maven (build tool)
Check if you have it:
```bash
mvn -version
```
If not installed, download from: https://maven.apache.org/download.cgi

### 3. Npcap (Windows only — required for packet capture)

> Npcap is the library that gives Java permission to read raw network packets.
> Without it, the app runs in DEMO MODE with simulated data.

1. Go to: https://npcap.com/#download
2. Download the latest Npcap installer
3. Run the installer
4. **IMPORTANT:** Check "Install Npcap in WinPcap API-compatible Mode" during installation
5. Restart your computer after installation

**Linux users:** Install libpcap instead:
```bash
sudo apt install libpcap-dev   # Ubuntu/Debian
sudo yum install libpcap-devel # CentOS/RHEL
```

**Mac users:**
```bash
brew install libpcap
```

---

## 🚀 How to Run the Application

### Step 1: Open a terminal/command prompt

On Windows: Press `Win + R`, type `cmd`, press Enter
On Mac/Linux: Open Terminal

### Step 2: Navigate to the project folder
```bash
cd path/to/guardian
# Example: cd C:\Users\YourName\Downloads\guardian
```

### Step 3: Build and run with Maven
```bash
mvn spring-boot:run
```

This command:
- Downloads all dependencies listed in pom.xml (first run takes a few minutes)
- Compiles all Java files
- Starts the embedded web server on port 8080

> ⚠️ **Windows users:** You may need to run the terminal as Administrator
> for Npcap to work. Right-click Command Prompt → "Run as administrator"

### Step 4: Open the dashboard
Open your browser and visit:
```
http://localhost:8080
```

You should see the Guardian dashboard with live data!

---

## 🎭 Demo Mode (No Npcap Required)

If packet capture fails (Npcap not installed, or missing permissions),
Guardian automatically switches to **Demo Mode**:
- Generates simulated network traffic
- All UI features work exactly the same
- Great for testing the frontend without worrying about system permissions

You'll see this in the console:
```
⚠️  Could not start packet capture
   Switching to DEMO MODE with simulated data.
🎭 Starting DEMO MODE...
```

---

## 🌐 API Reference

Once the app is running, you can test these APIs directly in your browser:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `http://localhost:8080/status` | GET | Check if backend is online |
| `http://localhost:8080/traffic` | GET | Packets per second (last 10s) |
| `http://localhost:8080/connections` | GET | Recent IP connections |

Example: Visit `http://localhost:8080/traffic` in your browser to see raw JSON.

---

## ❓ Troubleshooting

### "Port 8080 already in use"
Change the port in `src/main/resources/application.properties`:
```properties
server.port=9090
```
Then visit `http://localhost:9090` instead.

### "No network interfaces found"
- Windows: Make sure Npcap is installed and you restarted after installing
- Linux/Mac: Install libpcap (see above)
- Try running as administrator

### "CORS error in browser console"
Make sure you're opening the dashboard at `http://localhost:8080`
(served by Spring Boot), not by opening the HTML file directly.

### Maven download is slow
This is normal on first run. Maven downloads ~50MB of libraries.
Subsequent runs are instant (files are cached).

---

## 💡 How to Customize

**Change refresh rate** (in `index.html`, near the bottom):
```javascript
setInterval(refresh, 1000);  // Change 1000 to 2000 for every 2 seconds
```

**Change how many seconds to show** (in `TrafficService.java`):
```java
private static final int WINDOW_SECONDS = 10;  // Change to 30 for 30 seconds
```

**Change the port** (in `application.properties`):
```properties
server.port=8080
```

---

## 🎓 What You Learn From This Project

| Concept | Where It's Used |
|---------|-----------------|
| Spring Boot REST API | TrafficController.java |
| Background threads | TrafficService.java (captureThread) |
| Thread-safe data structures | CopyOnWriteArrayList |
| Packet capture | Pcap4j library |
| Fetch API (HTTP requests) | index.html — fetchTrafficData() |
| Real-time UI updates | setInterval() in JavaScript |
| Chart.js data visualization | trafficChart in index.html |
| JSON data exchange | Controller returns Map → becomes JSON |

---

*Built with ❤️ as a beginner-friendly network security project*
