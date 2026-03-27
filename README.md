# 🔐 Secure Network Diagnostic System (SSL + Raw Sockets)

## 📌 Overview
This project implements a **secure client-server system** using **SSL/TLS** that performs network diagnostic operations such as:

- 📡 Ping (ICMP Echo)
- 📍 Traceroute (TTL-based routing)
- 📊 Performance Metrics (RTT, Latency, Throughput)

The system combines **transport-layer security** with **network-layer diagnostics**, demonstrating low-level socket programming, ICMP handling, and multithreading.

---

## 🧠 Features

- 🔐 Secure communication using **OpenSSL (TLS)**
- 📡 Raw socket implementation of **Ping**
- 📍 Custom **Traceroute** using TTL manipulation
- 📊 Performance metrics:
  - Response Time
  - Throughput
  - Packet Loss
  - RTT (Min / Max / Average)
- 🧵 Multi-client handling using **pthread**
- 🌍 Multi-destination support  
  Example: `PING google.com amazon.com`

---

## 🏗️ System Architecture

```
Client → SSL Connection → Server
        ↓
   Command Input (PING / TRACEROUTE)
        ↓
   Raw Socket Processing (ICMP)
        ↓
   Performance Metrics Calculation
        ↓
   Encrypted Response (SSL)
```

---

## ⚙️ Technologies Used

- C Programming
- POSIX Sockets
- OpenSSL (TLS/SSL)
- Pthreads (Multithreading)
- ICMP Protocol (Raw Sockets)

---

## 📂 File Structure

```
.
├── secure_server.c     # Server code
├── client.c            # Client code
├── server.crt          # SSL certificate
├── server.key          # Private key
└── README.md
```

---

## 🔧 Installation (Mac - Apple Silicon)

### 1. Install OpenSSL
```bash
brew install openssl
```

---

## 🛠️ Compilation

### 🔹 Compile Server
```bash
gcc secure_server.c -o server \
-I/opt/homebrew/opt/openssl/include \
-L/opt/homebrew/opt/openssl/lib \
-lssl -lcrypto -lpthread
```

### 🔹 Compile Client
```bash
gcc client.c -o client \
-I/opt/homebrew/opt/openssl/include \
-L/opt/homebrew/opt/openssl/lib \
-lssl -lcrypto
```

---

## ▶️ Running the Program

### 🔹 Start Server (Requires root privileges)
```bash
sudo ./server
```

### 🔹 Run Client
```bash
./client
```

---

## 💻 Usage

### Example Commands:
```bash
PING google.com
PING google.com amazon.com
TRACEROUTE google.com
```

---

## 📊 Sample Output

### 🔹 Ping Output
```
64 bytes from 142.250.x.x: time=20.12 ms
64 bytes from 142.250.x.x: time=21.03 ms

Packets Sent: 4
Packets Received: 4
Packet Loss: 0%
RTT Avg: 20.57 ms | Min: 20.12 ms | Max: 21.03 ms
```

---

### 🔹 Traceroute Output
```
1  192.168.1.1   1.20 ms
2  10.0.0.1      5.40 ms
3  172.16.0.1    10.22 ms
4  142.250.x.x   20.85 ms
```

---

### 🔹 Performance Metrics
```
=== PERFORMANCE METRICS ===
Response Time: 4050.32 ms
Throughput: 0.25 req/sec
Total Requests: 5
Multi-Destination: 2
===========================
```

---

## 🧠 Key Concepts

### 🔹 Ping
- Uses **ICMP Echo Request/Reply**
- Measures **Round Trip Time (RTT)**

### 🔹 Traceroute
- Uses **TTL (Time-To-Live)**
- Identifies each network hop

### 🔹 Checksum
- Ensures **data integrity** of ICMP packets

### 🔹 SSL/TLS
- Encrypts communication between client and server

---

## ⚠️ Limitations

- Requires **root privileges** for raw sockets
- ICMP packets may be blocked by firewalls
- Uses deprecated `gethostbyname()` (can be improved)

---

## 🚀 Future Improvements

- Replace DNS with `getaddrinfo()`
- Add GUI interface
- Improve traceroute accuracy
- Add logging system
- Support IPv6

---

## 🎯 Learning Outcomes

- Low-level network programming
- Secure communication using SSL
- ICMP protocol handling
- Multithreaded server design
- Network performance analysis

---

## 👨‍💻 Author

Your Name

---

## 📜 License

This project is for educational purposes only.
