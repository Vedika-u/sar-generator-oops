# Automated Suspicious Activity Report (SAR) System 🛡️

A high-performance financial telemetry and risk evaluation engine built from scratch in **modern C++** using **Object-Oriented Programming (OOP)** and low-level **Winsock2 TCP socket networking**.

The system ingests banking transactions, calculates risk scores through polymorphic classification rules, flags anomalous financial behavior, and serves an interactive real-time monitoring dashboard over a custom multi-threaded HTTP server.

---

## 🚀 Key Features

* **Polymorphic Rule Engine:** Evaluates domestic transfers and international wire events using custom risk-scoring algorithms (unusual nocturnal hours, anomalous volumes, threshold spikes).
* **Zero-Dependency HTTP Server:** Custom web server implemented in C++ using the **Windows Sockets API (Winsock2)**, supporting concurrent client connections via std::thread.
* **Clean Object-Oriented Architecture:**
  * **Abstraction & Polymorphism:** Abstract base class BaseTransaction with virtual methods (calculateRiskScore(), getRiskCategory()).
  * **Inheritance:** Derived DomesticTransaction and InternationalWireTransaction implementations.
  * **Encapsulation & Memory Safety:** Thread-safe TransactionManager leveraging modern C++ smart pointers (std::shared_ptr) and mutex locks.
* **Real-time Web Dashboard:** Serves an embedded, dark-themed responsive telemetry dashboard directly on http://localhost:9090.

---

## 🛠️ Tech Stack & Concepts

* **Language:** C++ (C++17 standard)
* **Networking & Sockets:** Winsock2 (ws2_32.lib), TCP/IP Sockets, HTTP/1.1
* **Concurrency:** std::thread, std::mutex, std::lock_guard
* **Design Patterns:** Object-Oriented Design (OOP), Factory / Smart Pointer resource management

---

## ⚙️ Compilation & Execution

### 1. Prerequisites
* Windows OS
* MinGW / GCC (g++) or MSVC with C++17 support

### 2. Compile
`ash
g++ -std=c++17 sar_system.cpp -lws2_32 -o sar_system.exe
`

### 3. Run
`ash
./sar_system.exe
`

### 4. View Live Dashboard
Open your browser and navigate to:
`
http://localhost:9090
`

---

## 👤 Author
* **Vedika Utturwar** — [GitHub](https://github.com/Vedika-u) | [LinkedIn](https://www.linkedin.com/in/vedika-utturwar-b37b75336)
