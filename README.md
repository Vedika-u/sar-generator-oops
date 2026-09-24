# Design and Implementation of an Automated SAR Generation System Using OOPS

[![C++17](https://img.shields.io/badge/Language-C%2B%2B17-00599C?logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![Networking](https://img.shields.io/badge/Networking-Winsock2%20Sockets-blue)](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2)
[![Port](https://img.shields.io/badge/Port-9090-brightgreen)](http://localhost:9090)
[![Compliance](https://img.shields.io/badge/Compliance-FinCEN%20BSA%20SAR-orange)](https://www.fincen.gov/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An automated Suspicious Activity Reporting (SAR) monitoring and compliance system implemented entirely in **C++** using **Object-Oriented Programming (OOP)** principles and native **Winsock2** network sockets.

---

## 📌 Abstract

Suspicious Activity Reporting (SAR) is an important process in the banking sector to identify and report potentially fraudulent or illegal transactions. However, preparing SAR reports manually is time-consuming, error-prone, and requires significant human effort.

This project proposes an **Automated Suspicious Activity Reporting System based on Object-Oriented Programming (OOPS) principles**. The system collects transaction details, analyzes them using predefined rules, and automatically generates structured SAR reports.

Core OOPS concepts such as **class and object, encapsulation, abstraction, inheritance, and polymorphism** are used to model real-world entities like **users, transactions, analysts, and reports**. The system ensures data security, modularity, and easy extensibility.

The proposed solution reduces manual workload, improves reporting accuracy, and provides a scalable approach for handling large volumes of banking transactions.

---

## 🏛️ Mapping Real-World Entities to Core OOPS Concepts

The system architecture cleanly maps the banking problem domain into 4 core entities:

| Entity | OOPS Concept Demonstrated | Implementation in C++ |
| :--- | :--- | :--- |
| **1. User** | **Class, Object & Encapsulation** | `User` class with private credentials (`username`, `password`, `accountNumber`, `accountBalance`). Secure authentication methods. |
| **2. Transaction** | **Abstraction & Polymorphism** | Abstract base class `BaseTransaction` with pure virtual methods `isSuspicious()`, `getRiskCategory()`. Derived classes `NormalTransaction` and `SuspiciousTransaction` override behavior polymorphically. |
| **3. Analyst** | **Rule Engine & Decision Logic** | `Analyst` class encapsulating AML regulatory rules (e.g. Bank Secrecy Act statutory threshold of \$10,000) and generating structured SAR filings. |
| **4. Report** | **Data Modeling & Immutability** | `SARReport` class encapsulating official regulatory report fields: Report ID, Suspect Account, Flagged Amount, Reason, Recommended Action ("Freeze Account & Verify Identity"), and Timestamp. |

---

## 🖥️ System Interface (4 Switchable Tabs)

The C++ Winsock web server serves an interactive, responsive dashboard accessible on **`http://localhost:9090`** featuring 4 seamless switchable tabs:

1. **👤 1. Customer Login (User Entity):**
   * Secure user authentication module.
   * Pre-configured test accounts: `alice` (pass: `1234`) and `bob` (pass: `5678`).
   * Displays account balance and account routing number upon successful login.

2. **💳 2. Transaction History (Transaction Entity):**
   * Displays previous transactions stored in C++ memory (including initial records: \$3,000, \$4,500, and \$12,000).
   * Status indicators for cleared vs. flagged transactions.

3. **🔍 3. AML Analyst & Rules (Analyst Entity):**
   * Predefined regulatory rule evaluation.
   * Interactive input form to enter transaction amounts and test AML detection rules in real-time.
   * Amounts $> \$10,000$ automatically trigger regulatory alerts.

4. **📑 4. Generated SAR Reports (Report Entity):**
   * Lists generated formal Suspicious Activity Reports.
   * Displays detailed justification, flagged sums, legal regulatory reference (31 U.S.C. 5318(g)), and compliance recommended actions (*"Freeze Account & Verify Identity"*).

---

## 🚀 How to Run & Test

### Prerequisites
* Windows OS
* `g++` (MinGW / MSYS2 / GCC) with C++17 support

### Step-by-Step Execution

1. **Open Terminal / Command Prompt in project directory:**
   ```powershell
   cd sar-generator-oops
   ```

2. **Compile the C++ Single-File Code:**
   ```powershell
   g++ -std=c++17 sar_system.cpp -lws2_32 -o sar_system.exe
   ```

3. **Run the Binary:**
   ```powershell
   .\sar_system.exe
   ```

4. **Open in Browser:**
   Navigate to: **[http://localhost:9090](http://localhost:9090)**

5. **Stop Server:**
   Press `Ctrl + C` in the terminal when done.

---

## 👩‍💻 Author

**Vedika Utturwar**  
* B.Tech Information Technology, Banasthali Vidyapith (9.61 CGPA)
* Focus: C++, Object-Oriented Design, High-Performance Systems
* [GitHub Profile](https://github.com/Vedika-u)
