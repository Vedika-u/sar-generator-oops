# Design and Implementation of an Automated SAR Generation System Using OOPS

[![C++17](https://img.shields.io/badge/Language-C%2B%2B17-00599C?logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![Networking](https://img.shields.io/badge/Networking-Winsock2%20Sockets-blue)](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2)
[![Port](https://img.shields.io/badge/Port-9090-brightgreen)](http://localhost:9090)
[![Compliance](https://img.shields.io/badge/Compliance-FinCEN%20BSA%20SAR-orange)](https://www.fincen.gov/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade, automated **Suspicious Activity Reporting (SAR)** compliance and Anti-Money Laundering (AML) monitoring system engineered in **C++** using **Object-Oriented Programming (OOPS)** principles and native **Winsock2** network sockets.

---

## 📌 Abstract

Suspicious Activity Reporting (SAR) is an important process in the banking sector to identify and report potentially fraudulent or illegal transactions. However, preparing SAR reports manually is time-consuming, error-prone, and requires significant human effort.

This project proposes an **Automated Suspicious Activity Reporting System based on Object-Oriented Programming (OOPS) principles**. The system collects transaction details, analyzes them using predefined rules, and automatically generates structured SAR reports.

Core OOPS concepts such as **class and object, encapsulation, abstraction, inheritance, and polymorphism** are used to model real-world entities like **users, transactions, analysts, and reports**. The system ensures data security, modularity, and easy extensibility.

The proposed solution reduces manual workload, improves reporting accuracy, and provides a scalable approach for handling large volumes of banking transactions.

---

## 🏛️ Mapping Real-World Entities to Core OOPS Architecture

| Real-World Entity | Core OOPS Concept | Implementation Details |
| :--- | :--- | :--- |
| **1. User** | **Class, Object & Encapsulation** | `User` class with private credentials, dynamic runtime registration, balance management, and multi-state security transitions (`ACTIVE`, `TEMPORARY_HOLD`, `FROZEN`). |
| **2. Transaction** | **Abstraction & Polymorphism** | Abstract base class `BaseTransaction` defining pure virtual methods (`isSuspicious()`, `calculateRiskScore()`, `getTransactionType()`). Derived polymorphic classes: `NormalTransaction`, `HighValueTransaction`, `SanctionedTransaction`. |
| **3. Analyst** | **Rule Engine & Decision Logic** | `Analyst` class encapsulating AML regulatory checks, statutory BSA \$10,000 threshold verification, and real-time **OFAC / UN Sanctions Watchlist Screening**. |
| **4. Report** | **Data Modeling & Immutability** | `SARReport` class modeling regulatory FinCEN Form 111 electronic reports: Report ID, Suspect Entity, Flagged Amount, Violation Justification, Recommended Action, and Audit Trail. |
| **5. Manager** | **Concurrency & State Machine** | `SARSystemManager` coordinating thread-safe operations via `std::mutex`, managing multi-customer datasets, and tracking ledger state. |

---

## ⚡ Real-World Banking & Security Features

### 1. Dynamic User Registration & Multi-Customer Dataset
* Pre-populated with realistic diverse banking customers:
  * **Alice Sharma** (`alice` / `1234`) &bull; Balance: \$24,500 &bull; Consumer Account
  * **Vikram Malhotra** (`vikram` / `1234`) &bull; Balance: \$45,000 &bull; Tech Freelancer
  * **Charlie Brown** (`charlie` / `1234`) &bull; Balance: \$150,000 &bull; Commercial Importer
  * **Diana Prince** (`diana` / `1234`) &bull; Balance: \$500,000 &bull; High Net Worth
* **Dynamic Registration:** Allows any user to open a new account at runtime with custom credentials and initial deposits, dynamically instantiated as C++ objects.

### 2. 3-Tier Security State Machine & Emergency OTP Step-Up Challenge
To prevent freezing genuine customers during medical emergencies or legitimate high-value purchases (mitigating **False Positives**):
* **State 1 (`ACTIVE`):** Normal routine transactions cleared immediately.
* **State 2 (`TEMPORARY_HOLD`):** Transactions exceeding \$10,000 trigger a safety hold rather than a destructive hard freeze. An interactive **2FA OTP Step-Up Challenge** pops up:
  * Verified OTP + Declared Emergency Purpose (e.g. *Hospital Medical Emergency*) $\rightarrow$ **Hold Released & Transaction Cleared!**
  * Unverified / Aborted $\rightarrow$ Escalates to Hard Freeze and automated SAR Filing.
* **State 3 (`FROZEN`):** Confirmed fraudulent or non-compliant accounts locked under BSA Section 5318(g).

### 3. OFAC / UN Sanctions Watchlist Screening
* Evaluates all transfer targets against a global sanctions watchlist (`Darknet-Crypto-Mixer`, `Tornado-Cash-Vault`, `Lazarus-Hacker-Group`).
* Any transfer to a sanctioned entity is immediately blocked, triggering a mandatory Federal SAR filing regardless of transaction amount.

### 4. Live Dynamic Risk Speedometer (0% to 100%)
* Real-time animated risk meter that dynamically recalculates risk factors based on transfer volume, channel, and counterparty.

### 5. Compliance Officer Action Center & 1-Click SAR Download
* Compliance officers can review flagged transfers, grant emergency exemptions (**"Verify & Release Hold"**), confirm hard freezes, and download official **FinCEN Form 111 text filings** with a single click.

---

## 🖥️ System Interface (4 Seamless Switchable Tabs)

Accessible on **`http://localhost:9090`**:

1. **👤 1. Customer Portal:** Login, account creation, quick-login demo chips, live balance display, and fund transfer execution.
2. **💳 2. Transaction Ledger:** Consolidated transaction history with status badges (`Cleared`, `Hold`, `Blocked`).
3. **🔍 3. AML Rules & OTP:** Predefined statutory rule sets, live animated risk speedometer, and simulated emergency flow testing.
4. **📑 4. Compliance SAR Reports:** Generated regulatory reports, auditor override buttons, and 1-click `.txt` SAR report downloads.

---

## 🚀 How to Run & Test

### Prerequisites
* Windows OS
* `g++` (MinGW / MSYS2 / GCC) with C++17 support

### Execution Commands

1. **Open Terminal in project directory:**
   ```powershell
   cd sar-generator-oops
   ```

2. **Compile with Winsock2 Library:**
   ```powershell
   g++ -std=c++17 sar_system.cpp -lws2_32 -o sar_system.exe
   ```

3. **Run the Application:**
   ```powershell
   .\sar_system.exe
   ```

4. **Open in Browser:**
   Navigate to: **[http://localhost:9090](http://localhost:9090)**

5. **Stop Server:**
   Press `Ctrl + C` in the terminal when finished.

---

## 👩‍💻 Author

**Vedika Utturwar**  
* B.Tech Information Technology, Banasthali Vidyapith (9.61 CGPA)
* Focus: High-Performance Systems, C++, Object-Oriented Design, Concurrency
* [GitHub Profile](https://github.com/Vedika-u)
