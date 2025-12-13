````markdown
# macOS ARP Spoofing & HTTP Sniffer (PoC)

![Platform](https://img.shields.io/badge/platform-macOS-lightgrey)
![Language](https://img.shields.io/badge/language-C-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A lightweight, automated Man-in-the-Middle (MITM) attack tool written in C, specifically optimized for **macOS (BSD-based systems)**.

This project demonstrates the vulnerabilities of the ARP protocol and unencrypted HTTP traffic within a Local Area Network (LAN). It features automated target discovery, aggressive bidirectional spoofing to bypass modern OS defenses, and kernel-level packet forwarding for stealthy operation.

---

## ⚠️ Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY.**

This software is developed as a Proof-of-Concept (PoC) for network security research and protocol analysis.
* **Do not use this tool on networks you do not own or have explicit permission to test.**
* The author assumes no responsibility for any misuse or damage caused by this program.
* Please ensure you comply with all local laws and regulations regarding network security testing.

---

## 🌟 Key Features

* **🛡 macOS Optimized**: Built from the ground up for the BSD network stack, utilizing custom protocol structures to resolve header incompatibilities with Linux.
* **🚀 Automated Network Scanning**: Actively probes the subnet (Active Probing) to automatically discover and lock onto victim devices without manual IP entry.
* **⚡️ Aggressive Spoofing**: Implements high-frequency ARP injections (100ms interval) to counter ARP healing/recovery mechanisms found in modern mobile OS (iOS/Android).
* **👻 Stealthy Kernel Forwarding**: Leverages macOS native `sysctl` IP forwarding to route traffic via the kernel, ensuring zero latency and preventing victim disconnection (DoS).
* **🔍 Dynamic HTTP Sniffing**: Supports customizable keyword arguments to sniff specific fields (e.g., `username`, `password`, `token`) from HTTP POST payloads.
* **🧹 Smart De-duplication**: Includes application-level logic to filter out TCP retransmission packets, ensuring clean and readable log files.

---

## 🛠 Prerequisites

* **OS**: macOS (Tested on macOS Sequoia / Sonoma)
* **Compiler**: GCC / Clang
* **Library**: `libpcap`

To install dependencies on macOS using Homebrew:
```bash
brew install libpcap
```
````

-----

## 📦 Compilation

The project uses a standard `Makefile` for easy compilation.

```bash
# Compile the project
make

# Clean build files
make clean
```

-----

## 🚀 Usage

The tool requires **root privileges** (`sudo`) to open raw sockets and modify network settings.

### Syntax

```bash
sudo ./mac_mitm <Interface> <Target Website IP> <User Key> <Pass Key> [Victim IP]
```

### Arguments

  * `<Interface>`: Network interface name (e.g., `en0`, `en1`).
  * `<Target Website IP>`: The IP address of the HTTP server you want to monitor.
  * `<User Key>`: The form field name for the username (e.g., `username`, `uname`, `email`).
  * `<Pass Key>`: The form field name for the password (e.g., `password`, `pwd`, `pass`).
  * `[Victim IP]` (Optional): Specify a single victim IP. If omitted, **Auto-Scan Mode** is enabled.

### Examples

#### 1\. Auto-Scan Mode (Recommended)

Automatically scans the LAN, waits for a new device to join/act, and attacks it.

```bash
# Target: 44.228.249.3 (Example Vulnerable Site)
# Fields to sniff: "uname" and "pass"
sudo ./mac_mitm en0 44.228.249.3 uname pass
```

#### 2\. Manual Target Mode

Attacks a specific IP address immediately.

```bash
# Target: 44.228.249.3
# Victim: 192.168.1.105
sudo ./mac_mitm en0 44.228.249.3 username password 192.168.1.105
```

-----

## 🔧 Technical Details

### Architecture

The system operates using a multi-threaded architecture to ensure non-blocking performance:

1.  **Scanner Thread**: Broadcasts ARP requests to map the network and identify active hosts.
2.  **Spoofer Thread**: Sends forged ARP replies to both the victim and the gateway (Bidirectional Spoofing).
3.  **Sniffer Thread**: Captures and analyzes traffic using `libpcap` with Deep Packet Inspection (DPI) logic.

### Protocol Handling

Due to differences between Linux (`linux/if_ether.h`) and macOS (`net/ethernet.h`) headers, this project defines custom protocol structs (`my_ethhdr`, `my_arphdr`) with `__attribute__((packed))` to ensure precise memory alignment and cross-platform compatibility.

### Traffic Forwarding

Instead of forwarding packets in user space (which is slow and error-prone), this tool enables kernel-level forwarding for maximum performance:

```c
// Enabling IP forwarding via sysctl
sysctl -w net.inet.ip.forwarding=1
```

-----

## 📂 Project Structure

  * `src/` - Source code (`main.c`, `arp.c`, `sniffer.c`, `tools.c`).
  * `headers/` - Header files and custom struct definitions.
  * `makefile` - Build script.

-----

## 📝 License

This project is licensed under the MIT License.

```
```