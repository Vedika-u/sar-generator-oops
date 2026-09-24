#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include <iomanip>
#include <mutex>
#include <unordered_map>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

// ============================================================================
// PROJECT: Design and Implementation of an Automated SAR Generation System Using OOPS
// 
// CORE OOPS ENTITIES:
//   1. User (Class & Object, Encapsulation, Dynamic Account Registration)
//   2. BaseTransaction (Abstraction & Polymorphism with Derived Classes)
//   3. Analyst (Compliance Rule Engine, Sanctions Watchlist, Risk Scoring)
//   4. SARReport (Structured Legal Suspicious Activity Report Entity)
//   5. SARSystemManager (Central Thread-Safe Coordinator & State Machine)
// ============================================================================

enum class AccountStatus {
    ACTIVE,
    TEMPORARY_HOLD,
    FROZEN
};

inline string statusToString(AccountStatus status) {
    switch (status) {
        case AccountStatus::ACTIVE: return "ACTIVE";
        case AccountStatus::TEMPORARY_HOLD: return "TEMPORARY_HOLD";
        case AccountStatus::FROZEN: return "FROZEN";
        default: return "UNKNOWN";
    }
}

// ----------------------------------------------------------------------------
// 1. ENTITY: User (Demonstrates Class, Object, & Encapsulation)
// ----------------------------------------------------------------------------
class User {
private:
    string username;
    string password;
    string fullName;
    string accountNumber;
    double accountBalance;
    string country;
    AccountStatus status;

public:
    User(string u, string p, string name, string acc, double bal, string ctry = "IN")
        : username(u), password(p), fullName(name), accountNumber(acc), 
          accountBalance(bal), country(ctry), status(AccountStatus::ACTIVE) {}

    bool authenticate(const string& u, const string& p) const {
        return (username == u && password == p);
    }

    // Getters (Encapsulation)
    string getUsername() const { return username; }
    string getFullName() const { return fullName; }
    string getAccountNumber() const { return accountNumber; }
    double getBalance() const { return accountBalance; }
    string getCountry() const { return country; }
    AccountStatus getStatus() const { return status; }

    // State Machine Transitions
    void setStatus(AccountStatus s) { status = s; }
    void debit(double amt) { accountBalance -= amt; }
    void credit(double amt) { accountBalance += amt; }
};

// ----------------------------------------------------------------------------
// 2. ENTITY: BaseTransaction (Demonstrates Abstraction & Polymorphism)
// ----------------------------------------------------------------------------
class BaseTransaction {
protected:
    string txnId;
    string sender;
    string recipient;
    double amount;
    string timestamp;
    string country;

public:
    BaseTransaction(string id, string from, string to, double amt, string time, string ctry = "US")
        : txnId(id), sender(from), recipient(to), amount(amt), timestamp(time), country(ctry) {}

    virtual ~BaseTransaction() = default;

    // Pure virtual functions (Abstraction)
    virtual bool isSuspicious() const = 0;
    virtual double calculateRiskScore() const = 0;
    virtual string getRiskCategory() const = 0;
    virtual string getTransactionType() const = 0;

    string getId() const { return txnId; }
    string getSender() const { return sender; }
    string getRecipient() const { return recipient; }
    double getAmount() const { return amount; }
    string getTimestamp() const { return timestamp; }
    string getCountry() const { return country; }
};

// Derived Class 1: Standard Normal Transaction (Demonstrates Inheritance)
class NormalTransaction : public BaseTransaction {
public:
    NormalTransaction(string id, string from, string to, double amt, string time, string ctry = "US")
        : BaseTransaction(id, from, to, amt, time, ctry) {}

    bool isSuspicious() const override {
        return false;
    }

    double calculateRiskScore() const override {
        return 15.0; // Low baseline risk
    }

    string getRiskCategory() const override {
        return "Normal / Verified";
    }

    string getTransactionType() const override {
        return "Standard Domestic Clearing";
    }
};

// Derived Class 2: High-Value Transaction (Polymorphism: Overrides threshold checks)
class HighValueTransaction : public BaseTransaction {
public:
    HighValueTransaction(string id, string from, string to, double amt, string time, string ctry = "US")
        : BaseTransaction(id, from, to, amt, time, ctry) {}

    bool isSuspicious() const override {
        return (amount > 10000.0);
    }

    double calculateRiskScore() const override {
        double score = 40.0;
        if (amount > 10000.0) score += 35.0;
        if (amount > 50000.0) score += 20.0;
        return min(100.0, score);
    }

    string getRiskCategory() const override {
        return (amount > 10000.0) ? "ELEVATED (BSA CTR / SAR REQUIRED)" : "MODERATE";
    }

    string getTransactionType() const override {
        return "High-Value Commercial Wire";
    }
};

// Derived Class 3: Sanctioned / Blacklisted Entity Transfer (Polymorphism)
class SanctionedTransaction : public BaseTransaction {
private:
    string matchedWatchlistEntity;

public:
    SanctionedTransaction(string id, string from, string to, double amt, string time, string matchedEntity)
        : BaseTransaction(id, from, to, amt, time, "GLOBAL_WATCHLIST"), matchedWatchlistEntity(matchedEntity) {}

    bool isSuspicious() const override {
        return true;
    }

    double calculateRiskScore() const override {
        return 99.0; // Maximum Critical Risk
    }

    string getRiskCategory() const override {
        return "CRITICAL: OFAC SANCTIONS HIT";
    }

    string getTransactionType() const override {
        return "Blacklisted Entity Direct Transfer";
    }

    string getMatchedEntity() const { return matchedWatchlistEntity; }
};

// ----------------------------------------------------------------------------
// 3. ENTITY: SARReport (Structured Suspicious Activity Report)
// ----------------------------------------------------------------------------
class SARReport {
private:
    string reportId;
    string subjectUser;
    string suspectAccount;
    string recipient;
    double flaggedAmount;
    string violationType;
    string detectionReason;
    string recommendedAction;
    string filingDate;
    string complianceStatus; // "UNDER_AUDIT", "CLEARED_EMERGENCY", "CONFIRMED_FROZEN"

public:
    SARReport(string id, string user, string acc, string rec, double amt, string vType, string reason, string action, string date)
        : reportId(id), subjectUser(user), suspectAccount(acc), recipient(rec), flaggedAmount(amt),
          violationType(vType), detectionReason(reason), recommendedAction(action), 
          filingDate(date), complianceStatus("UNDER_AUDIT") {}

    string getReportId() const { return reportId; }
    string getSubject() const { return subjectUser; }
    string getAccount() const { return suspectAccount; }
    string getRecipient() const { return recipient; }
    double getAmount() const { return flaggedAmount; }
    string getViolationType() const { return violationType; }
    string getReason() const { return detectionReason; }
    string getAction() const { return recommendedAction; }
    string getDate() const { return filingDate; }
    string getComplianceStatus() const { return complianceStatus; }

    void setComplianceStatus(const string& s) { complianceStatus = s; }
    void setRecommendedAction(const string& a) { recommendedAction = a; }
};

// ----------------------------------------------------------------------------
// 4. ENTITY: Analyst (Rule Engine & Sanctions Screening)
// ----------------------------------------------------------------------------
class Analyst {
public:
    static const vector<string>& getSanctionsWatchlist() {
        static const vector<string> watchlist = {
            "Darknet-Crypto-Mixer",
            "Offshore-Sanctioned-Corp",
            "Lazarus-Hacker-Group",
            "Tornado-Cash-Vault",
            "Al-Zahra-Shadow-Trade"
        };
        return watchlist;
    }

    static bool isSanctioned(const string& recipient, string& matchedEntity) {
        const auto& list = getSanctionsWatchlist();
        for (const auto& entry : list) {
            if (recipient.find(entry) != string::npos || entry.find(recipient) != string::npos) {
                matchedEntity = entry;
                return true;
            }
        }
        return false;
    }

    static shared_ptr<SARReport> generateSAR(
        int reportSeq, 
        const string& user, 
        const string& acc, 
        const string& recipient, 
        double amt, 
        const string& violationType,
        const string& reason,
        const string& action
    ) {
        string repId = "SAR-2026-" + to_string(100 + reportSeq);
        string date = "2026-09-25 10:15:00 UTC";
        return make_shared<SARReport>(repId, user, acc, recipient, amt, violationType, reason, action, date);
    }
};

// ----------------------------------------------------------------------------
// 5. SYSTEM MANAGER: Central State Machine & Multi-User Data Engine
// ----------------------------------------------------------------------------
class SARSystemManager {
private:
    unordered_map<string, User> users;
    vector<shared_ptr<BaseTransaction>> transactions;
    vector<shared_ptr<SARReport>> sarReports;
    mutex mtx;
    int reportCounter{0};

public:
    SARSystemManager() {
        // Multi-Customer Dataset (Realistic starting accounts)
        users.emplace("alice", User("alice", "1234", "Alice Sharma", "ACC-789012", 24500.0, "IN"));
        users.emplace("vikram", User("vikram", "1234", "Vikram Malhotra", "ACC-345678", 45000.0, "IN"));
        users.emplace("charlie", User("charlie", "1234", "Charlie Brown", "ACC-901234", 150000.0, "US"));
        users.emplace("diana", User("diana", "1234", "Diana Prince", "ACC-567890", 500000.0, "GB"));

        // Pre-populated transactions including previous historical dataset ($3000, $4500, $12000)
        transactions.push_back(make_shared<NormalTransaction>("TXN-101", "Alice Sharma (ACC-789012)", "Retail Grocery Mart", 3000.0, "2026-09-24 14:20", "IN"));
        transactions.push_back(make_shared<NormalTransaction>("TXN-102", "Alice Sharma (ACC-789012)", "Vikram Malhotra (ACC-345678)", 4500.0, "2026-09-24 16:45", "IN"));
        transactions.push_back(make_shared<HighValueTransaction>("TXN-103", "Alice Sharma (ACC-789012)", "Offshore Asset Management", 12000.0, "2026-09-24 19:10", "KY"));
        transactions.push_back(make_shared<SanctionedTransaction>("TXN-104", "Charlie Brown (ACC-901234)", "Darknet-Crypto-Mixer", 8500.0, "2026-09-24 21:05", "Darknet-Crypto-Mixer"));

        // Pre-populate initial SAR reports for existing suspicious transactions
        sarReports.push_back(Analyst::generateSAR(
            ++reportCounter, "alice", "ACC-789012", "Offshore Asset Management", 12000.0,
            "STATUTORY THRESHOLD VIOLATION",
            "Single transfer of $12,000 exceeds the $10,000 Bank Secrecy Act statutory CTR limit.",
            "Temporary Hold Initiated. Review for Emergency Medical or Commercial Exemption."
        ));

        sarReports.push_back(Analyst::generateSAR(
            ++reportCounter, "charlie", "ACC-901234", "Darknet-Crypto-Mixer", 8500.0,
            "OFAC FEDERAL SANCTIONS VIOLATION",
            "Recipient matched against Global OFAC / UN Specially Designated Nationals (SDN) Watchlist.",
            "CRITICAL: Immediate Hard Freeze & Asset Lock Required under Executive Order 13694."
        ));
    }

    bool registerNewUser(const string& u, const string& p, const string& name, double bal, const string& ctry) {
        lock_guard<mutex> lock(mtx);
        if (users.find(u) != users.end()) return false; // Already exists

        string acc = "ACC-" + to_string(100000 + rand() % 899999);
        users.emplace(u, User(u, p, name, acc, bal, ctry));
        return true;
    }

    string getInitialStateJSON() {
        lock_guard<mutex> lock(mtx);
        stringstream ss;
        ss << "{\n  \"users\": [\n";
        size_t idx = 0;
        for (const auto& pair : users) {
            const auto& u = pair.second;
            ss << "    {\"username\": \"" << u.getUsername() 
               << "\", \"name\": \"" << u.getFullName()
               << "\", \"account\": \"" << u.getAccountNumber()
               << "\", \"balance\": " << fixed << setprecision(2) << u.getBalance()
               << ", \"country\": \"" << u.getCountry()
               << "\", \"status\": \"" << statusToString(u.getStatus()) << "\"}";
            if (++idx < users.size()) ss << ",";
            ss << "\n";
        }
        ss << "  ]\n}";
        return ss.str();
    }
};

// ----------------------------------------------------------------------------
// 6. EMBEDDED HIGH-TECH BANKING INVESTIGATION INTERFACE (HTML/CSS/JS)
// ----------------------------------------------------------------------------
string buildCompleteWebPage(SARSystemManager& mgr) {
    string stateJson = mgr.getInitialStateJSON();

    stringstream page;
    page << "HTTP/1.1 200 OK\r\n"
         << "Content-Type: text/html\r\n"
         << "Connection: close\r\n\r\n"
         << "<!DOCTYPE html>\n"
         << "<html lang='en'>\n"
         << "<head>\n"
         << "  <meta charset='UTF-8'>\n"
         << "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
         << "  <title>Automated SAR Generation System Using OOPS</title>\n"
         << "  <link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap' rel='stylesheet'>\n"
         << "  <style>\n"
         << "    :root {\n"
         << "      --bg-main: #0b0f19; --bg-card: #121826; --border: #232d42;\n"
         << "      --text-main: #f8fafc; --text-muted: #94a3b8; --accent-blue: #38bdf8;\n"
         << "      --danger: #ef4444; --warning: #f59e0b; --success: #10b981;\n"
         << "      --font-sans: 'Plus Jakarta Sans', sans-serif;\n"
         << "      --font-mono: 'JetBrains Mono', monospace;\n"
         << "    }\n"
         << "    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
         << "    body { background: var(--bg-main); color: var(--text-main); font-family: var(--font-sans); padding: 24px; min-height: 100vh; }\n"
         << "    .container { max-width: 1100px; margin: 0 auto; }\n"
         << "    \n"
         << "    /* Header Bar */\n"
         << "    .navbar { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 20px; }\n"
         << "    .brand-title { font-size: 22px; font-weight: 800; color: var(--accent-blue); display: flex; align-items: center; gap: 10px; }\n"
         << "    .badge-cpp { background: #1e1b4b; color: #a5b4fc; font-family: var(--font-mono); font-size: 11px; padding: 3px 8px; border-radius: 4px; border: 1px solid #3730a3; }\n"
         << "    .live-status { display: flex; align-items: center; gap: 8px; background: #111827; padding: 6px 14px; border-radius: 20px; border: 1px solid var(--border); font-size: 13px; }\n"
         << "    .dot { width: 8px; height: 8px; background: var(--success); border-radius: 50%; box-shadow: 0 0 8px var(--success); animation: pulse 2s infinite; }\n"
         << "    @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }\n"
         << "    \n"
         << "    /* 4 Navigation Tabs */\n"
         << "    .tab-bar { display: flex; gap: 8px; background: #0f1523; padding: 6px; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 24px; }\n"
         << "    .tab-btn { flex: 1; padding: 12px 14px; background: transparent; border: none; color: var(--text-muted); font-size: 14px; font-weight: 700; cursor: pointer; border-radius: 8px; transition: all 0.2s; text-align: center; }\n"
         << "    .tab-btn:hover { color: #fff; background: #1e293b; }\n"
         << "    .tab-btn.active { background: #0284c7; color: #fff; box-shadow: 0 2px 10px rgba(2, 132, 199, 0.4); }\n"
         << "    \n"
         << "    /* Tab Contents */\n"
         << "    .tab-pane { display: none; background: var(--bg-card); border: 1px solid var(--border); border-radius: 14px; padding: 26px; animation: fadeIn 0.3s ease; }\n"
         << "    .tab-pane.active { display: block; }\n"
         << "    @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }\n"
         << "    \n"
         << "    /* Grid Layouts & Cards */\n"
         << "    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }\n"
         << "    @media (max-width: 850px) { .grid-2 { grid-template-columns: 1fr; } }\n"
         << "    .card-box { background: #0c121e; border: 1px solid var(--border); border-radius: 10px; padding: 18px; margin-bottom: 16px; }\n"
         << "    .card-title { font-size: 15px; font-weight: 700; color: #e2e8f0; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }\n"
         << "    \n"
         << "    /* Form Controls */\n"
         << "    label { display: block; font-size: 12px; font-weight: 700; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.04em; }\n"
         << "    input, select { width: 100%; padding: 11px 14px; background: #070a10; border: 1px solid var(--border); border-radius: 8px; color: #fff; font-size: 14px; margin-bottom: 14px; font-family: var(--font-sans); }\n"
         << "    input:focus, select:focus { outline: none; border-color: var(--accent-blue); }\n"
         << "    .btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; padding: 11px 20px; border-radius: 8px; font-weight: 700; font-size: 14px; cursor: pointer; border: none; transition: all 0.2s; font-family: var(--font-sans); }\n"
         << "    .btn-primary { background: #0284c7; color: #fff; }\n"
         << "    .btn-primary:hover { background: #0369a1; }\n"
         << "    .btn-success { background: #059669; color: #fff; }\n"
         << "    .btn-success:hover { background: #047857; }\n"
         << "    .btn-danger { background: #b91c1c; color: #fff; }\n"
         << "    .btn-danger:hover { background: #991b1b; }\n"
         << "    .btn-secondary { background: #1e293b; color: #cbd5e1; border: 1px solid var(--border); }\n"
         << "    .btn-secondary:hover { background: #334155; }\n"
         << "    .btn-block { width: 100%; }\n"
         << "    .btn-sm { padding: 6px 12px; font-size: 12px; }\n"
         << "    \n"
         << "    /* Badges & Tables */\n"
         << "    .badge { padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 800; font-family: var(--font-mono); display: inline-block; }\n"
         << "    .badge-success { background: #064e3b; color: #34d399; }\n"
         << "    .badge-warning { background: #78350f; color: #fbbf24; }\n"
         << "    .badge-danger { background: #7f1d1d; color: #fca5a5; }\n"
         << "    .badge-blue { background: #1e3a8a; color: #93c5fd; }\n"
         << "    \n"
         << "    table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }\n"
         << "    th { background: #0a0f18; padding: 10px 12px; color: var(--text-muted); font-size: 11px; text-transform: uppercase; font-weight: 700; border-bottom: 1px solid var(--border); }\n"
         << "    td { padding: 12px; border-bottom: 1px solid #1a2233; color: #cbd5e1; }\n"
         << "    \n"
         << "    /* Quick User Chips */\n"
         << "    .quick-users { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }\n"
         << "    .user-chip { background: #1e293b; border: 1px solid var(--border); padding: 8px 12px; border-radius: 8px; cursor: pointer; font-size: 12px; transition: all 0.2s; }\n"
         << "    .user-chip:hover { border-color: var(--accent-blue); background: #273549; }\n"
         << "    \n"
         << "    /* Risk Meter Gauge */\n"
         << "    .gauge-container { background: #080d16; border: 1px solid var(--border); border-radius: 12px; padding: 18px; text-align: center; margin-bottom: 20px; }\n"
         << "    .gauge-track { height: 16px; background: #1e293b; border-radius: 10px; overflow: hidden; margin: 12px 0; position: relative; }\n"
         << "    .gauge-fill { height: 100%; width: 15%; background: linear-gradient(90deg, #10b981, #f59e0b, #ef4444); transition: width 0.4s ease; border-radius: 10px; }\n"
         << "    .gauge-score { font-family: var(--font-mono); font-size: 32px; font-weight: 800; color: #fff; }\n"
         << "    \n"
         << "    /* Modals */\n"
         << "    .modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.85); backdrop-filter: blur(4px); z-index: 1000; align-items: center; justify-content: center; padding: 20px; }\n"
         << "    .modal.active { display: flex; }\n"
         << "    .modal-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 14px; width: 100%; max-width: 580px; padding: 24px; }\n"
         << "    \n"
         << "    .sar-card { background: #0a0e17; border: 1px solid #991b1b; border-left: 6px solid var(--danger); border-radius: 10px; padding: 18px; margin-bottom: 16px; }\n"
         << "    .sar-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }\n"
         << "    .sar-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 13px; color: #cbd5e1; margin-bottom: 12px; }\n"
         << "    .sar-reason { background: #1c1917; border: 1px solid #78350f; color: #fde68a; padding: 10px; border-radius: 6px; font-size: 13px; margin-bottom: 10px; }\n"
         << "    .sar-action { background: #2e1065; border: 1px solid #6b21a8; color: #e9d5ff; padding: 10px; border-radius: 6px; font-size: 13px; margin-bottom: 12px; font-weight: 600; }\n"
         << "    .sar-btns { display: flex; gap: 10px; flex-wrap: wrap; }\n"
         << "  </style>\n"
         << "</head>\n"
         << "<body>\n"
         << "  <div class='container'>\n"
         << "    <!-- NAVBAR -->\n"
         << "    <header class='navbar'>\n"
         << "      <div>\n"
         << "        <div class='brand-title'>🛡️ Automated SAR Generation System <span class='badge-cpp'>C++17 OOPS</span></div>\n"
         << "        <div style='color: var(--text-muted); font-size: 13px; margin-top: 4px;'>Design &amp; Implementation of Banking AML Monitoring &bull; Port 9090</div>\n"
         << "      </div>\n"
         << "      <div class='live-status'>\n"
         << "        <span class='dot'></span>\n"
         << "        <span>C++ Engine Active</span>\n"
         << "        <span style='color:var(--text-muted); font-family:var(--font-mono); margin-left:8px;'>BSA 31 U.S.C. 5318(g)</span>\n"
         << "      </div>\n"
         << "    </header>\n"
         << "    \n"
         << "    <!-- 4 TABS NAVIGATION -->\n"
         << "    <nav class='tab-bar'>\n"
         << "      <button class='tab-btn active' onclick=\"switchTab('tabPortal')\">👤 1. Customer Portal</button>\n"
         << "      <button class='tab-btn' onclick=\"switchTab('tabLedger')\">💳 2. Transaction Ledger</button>\n"
         << "      <button class='tab-btn' onclick=\"switchTab('tabRules')\">🔍 3. AML Rules &amp; OTP</button>\n"
         << "      <button class='tab-btn' onclick=\"switchTab('tabAuditor')\">📑 4. Compliance SAR Reports</button>\n"
         << "    </nav>\n"
         << "    \n"
         << "    <!-- TAB 1: CUSTOMER PORTAL & DYNAMIC ACCOUNTS -->\n"
         << "    <div id='tabPortal' class='tab-pane active'>\n"
         << "      <div class='grid-2'>\n"
         << "        <!-- Left: Authentication & Dynamic Registration -->\n"
         << "        <div class='card-box'>\n"
         << "          <div class='card-title'>\n"
         << "            <span>Authentication (User Entity)</span>\n"
         << "            <button class='btn btn-secondary btn-sm' onclick='toggleAuthMode()' id='authToggleBtn'>+ Create New Account</button>\n"
         << "          </div>\n"
         << "          \n"
         << "          <!-- Pre-populated Quick Login Chips -->\n"
         << "          <div style='font-size:12px; color:var(--text-muted); margin-bottom:8px;'>DEMO ONE-CLICK LOGIN:</div>\n"
         << "          <div class='quick-users'>\n"
         << "            <div class='user-chip' onclick=\"quickLogin('alice')\">👩 <strong>Alice</strong> ($24.5k)</div>\n"
         << "            <div class='user-chip' onclick=\"quickLogin('vikram')\">👨 <strong>Vikram</strong> ($45k)</div>\n"
         << "            <div class='user-chip' onclick=\"quickLogin('charlie')\">🏢 <strong>Charlie</strong> ($150k)</div>\n"
         << "            <div class='user-chip' onclick=\"quickLogin('diana')\">💎 <strong>Diana</strong> ($500k)</div>\n"
         << "          </div>\n"
         << "          \n"
         << "          <!-- Login Form -->\n"
         << "          <div id='loginSection'>\n"
         << "            <label>Username:</label>\n"
         << "            <input id='loginUser' placeholder='e.g. alice' value='alice'>\n"
         << "            <label>Password:</label>\n"
         << "            <input id='loginPass' type='password' placeholder='e.g. 1234' value='1234'>\n"
         << "            <button class='btn btn-primary btn-block' onclick='handleLogin()'>🔑 Secure Login</button>\n"
         << "          </div>\n"
         << "          \n"
         << "          <!-- Dynamic Registration Form -->\n"
         << "          <div id='registerSection' style='display:none;'>\n"
         << "            <label>Full Name:</label>\n"
         << "            <input id='regName' placeholder='e.g. Rohit Verma'>\n"
         << "            <label>Desired Username:</label>\n"
         << "            <input id='regUser' placeholder='e.g. rohit'>\n"
         << "            <label>Password:</label>\n"
         << "            <input id='regPass' type='password' placeholder='••••••••'>\n"
         << "            <label>Initial Opening Deposit ($):</label>\n"
         << "            <input id='regBal' type='number' placeholder='10000'>\n"
         << "            <button class='btn btn-success btn-block' onclick='handleRegister()'>✨ Create C++ Account Object</button>\n"
         << "          </div>\n"
         << "        </div>\n"
         << "        \n"
         << "        <!-- Right: Logged-in Profile & Fund Transfer -->\n"
         << "        <div class='card-box'>\n"
         << "          <div class='card-title'>\n"
         << "            <span>Active Customer Profile</span>\n"
         << "            <span id='userStatusBadge' class='badge badge-success'>ACTIVE</span>\n"
         << "          </div>\n"
         << "          \n"
         << "          <div id='profileDisplay' style='padding: 10px 0;'>\n"
         << "            <div style='font-size:20px; font-weight:800;' id='dispName'>Alice Sharma</div>\n"
         << "            <div style='font-family:var(--font-mono); color:var(--text-muted); font-size:13px; margin:4px 0 14px 0;' id='dispAcc'>Account: ACC-789012</div>\n"
         << "            <div style='background:#070a10; padding:16px; border-radius:8px; border:1px solid var(--border); margin-bottom:16px;'>\n"
         << "              <div style='font-size:12px; color:var(--text-muted);'>AVAILABLE BALANCE</div>\n"
         << "              <div style='font-size:28px; font-weight:800; font-family:var(--font-mono); color:#38bdf8;' id='dispBal'>$24,500.00</div>\n"
         << "            </div>\n"
         << "            \n"
         << "            <div class='card-title'>Initiate Fund Transfer</div>\n"
         << "            <label>Transfer Amount ($ USD):</label>\n"
         << "            <input id='transferAmt' type='number' placeholder='e.g. 15000' value='12000' oninput='updateRiskMeter(this.value)'>\n"
         << "            <label>Select or Enter Recipient:</label>\n"
         << "            <select id='transferRecipient'>\n"
         << "              <option value='Vikram Malhotra (ACC-345678)'>Vikram Malhotra (ACC-345678) - Domestic</option>\n"
         << "              <option value='Charlie Brown (ACC-901234)'>Charlie Brown (ACC-901234) - Domestic</option>\n"
         << "              <option value='Diana Prince (ACC-567890)'>Diana Prince (ACC-567890) - Domestic</option>\n"
         << "              <option value='Offshore Asset Management (KY)'>Offshore Asset Management (Cayman Islands)</option>\n"
         << "              <option value='Darknet-Crypto-Mixer'>Darknet-Crypto-Mixer (⚠️ Sanctions Blacklist)</option>\n"
         << "            </select>\n"
         << "            <button class='btn btn-primary btn-block' onclick='executeTransfer()'>⚡ Execute Transaction via OOPS Engine</button>\n"
         << "          </div>\n"
         << "        </div>\n"
         << "      </div>\n"
         << "    </div>\n"
         << "    \n"
         << "    <!-- TAB 2: TRANSACTION HISTORY LEDGER -->\n"
         << "    <div id='tabLedger' class='tab-pane'>\n"
         << "      <div class='card-title'>\n"
         << "        <span>Consolidated Banking Audit Ledger (BaseTransaction Polymorphism)</span>\n"
         << "        <span class='badge badge-blue'>Real-Time State</span>\n"
         << "      </div>\n"
         << "      <p style='color:var(--text-muted); font-size:13px; margin-bottom:16px;'>Every transfer passes through polymorphic abstraction (`NormalTransaction`, `HighValueTransaction`, `SanctionedTransaction`).</p>\n"
         << "      \n"
         << "      <div style='overflow-x:auto;'>\n"
         << "        <table>\n"
         << "          <thead>\n"
         << "            <tr><th>Txn ID</th><th>Sender &rarr; Recipient</th><th>Amount</th><th>Category / Type</th><th>Timestamp</th><th>Status</th></tr>\n"
         << "          </thead>\n"
         << "          <tbody id='ledgerTableBody'>\n"
         << "            <!-- Dynamic Table Rows -->\n"
         << "          </tbody>\n"
         << "        </table>\n"
         << "      </div>\n"
         << "    </div>\n"
         << "    \n"
         << "    <!-- TAB 3: AML COMPLIANCE RULES & OTP CHALLENGE -->\n"
         << "    <div id='tabRules' class='tab-pane'>\n"
         << "      <div class='grid-2'>\n"
         << "        <!-- Left: Active Banking Rules -->\n"
         << "        <div>\n"
         << "          <div class='card-title'>Active Banking Compliance Rules (Analyst Entity)</div>\n"
         << "          <div class='card-box'>\n"
         << "            <div style='font-size:14px; font-weight:700; color:#facc15; margin-bottom:4px;'>Rule 1: Statutory BSA Threshold ($10,000)</div>\n"
         << "            <div style='font-size:13px; color:var(--text-muted); line-height:1.4;'>Amounts exceeding $10,000 trigger an automated Temporary Safety Hold and require 2FA OTP Step-Up verification.</div>\n"
         << "          </div>\n"
         << "          <div class='card-box'>\n"
         << "            <div style='font-size:14px; font-weight:700; color:var(--danger); margin-bottom:4px;'>Rule 2: OFAC / UN Sanctions Watchlist</div>\n"
         << "            <div style='font-size:13px; color:var(--text-muted); line-height:1.4;'>Immediate blocking &amp; SAR filing if recipient matches: <em>Darknet-Crypto-Mixer, Tornado-Cash-Vault, Lazarus-Hacker-Group</em>.</div>\n"
         << "          </div>\n"
         << "          <div class='card-box'>\n"
         << "            <div style='font-size:14px; font-weight:700; color:#38bdf8; margin-bottom:4px;'>Rule 3: Emergency Exemption Bypass</div>\n"
         << "            <div style='font-size:13px; color:var(--text-muted); line-height:1.4;'>Legitimate emergencies (Medical, Real Estate) are verified through OTP without freezing customer assets!</div>\n"
         << "          </div>\n"
         << "        </div>\n"
         << "        \n"
         << "        <!-- Right: Dynamic Risk Speedometer -->\n"
         << "        <div>\n"
         << "          <div class='gauge-container'>\n"
         << "            <div style='font-size:13px; font-weight:700; color:var(--text-muted);'>LIVE DYNAMIC RISK METER</div>\n"
         << "            <div class='gauge-score' id='riskScoreText'>45%</div>\n"
         << "            <div class='gauge-track'>\n"
         << "              <div class='gauge-fill' id='riskGaugeBar' style='width: 45%;'></div>\n"
         << "            </div>\n"
         << "            <div id='riskLabel' style='font-size:13px; font-weight:700; color:var(--warning);'>ELEVATED THRESHOLD RISK</div>\n"
         << "          </div>\n"
         << "          \n"
         << "          <div class='card-box'>\n"
         << "            <div class='card-title'>Simulate Emergency Medical Exemption</div>\n"
         << "            <p style='font-size:13px; color:var(--text-muted); margin-bottom:12px;'>Test what happens when a customer has a genuine $25,000 hospital emergency transfer:</p>\n"
         << "            <button class='btn btn-warning btn-block' onclick='simulateEmergencyFlow()'>🏥 Test Emergency $25,000 Transfer</button>\n"
         << "          </div>\n"
         << "        </div>\n"
         << "      </div>\n"
         << "    </div>\n"
         << "    \n"
         << "    <!-- TAB 4: COMPLIANCE AUDITOR SAR REPORTS -->\n"
         << "    <div id='tabAuditor' class='tab-pane'>\n"
         << "      <div class='card-title'>\n"
         << "        <span>Regulatory Suspicious Activity Reports (SARReport Entity)</span>\n"
         << "        <span class='badge badge-danger' id='sarCountBadge'>2 ACTIVE REPORTS</span>\n"
         << "      </div>\n"
         << "      <p style='color:var(--text-muted); font-size:13px; margin-bottom:16px;'>Official SAR filings under 31 U.S.C. 5318(g). Compliance officers can investigate, unfreeze genuine emergencies, or confirm hard freezes.</p>\n"
         << "      \n"
         << "      <div id='sarReportCardsContainer'>\n"
         << "        <!-- Dynamic SAR Cards -->\n"
         << "      </div>\n"
         << "    </div>\n"
         << "  </div>\n"
         << "  \n"
         << "  <!-- EMERGENCY OTP STEP-UP MODAL -->\n"
         << "  <div id='otpModal' class='modal'>\n"
         << "    <div class='modal-box'>\n"
         << "      <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;'>\n"
         << "        <div style='font-size:18px; font-weight:800; color:#facc15;'>🚨 High-Value Step-Up 2FA Challenge</div>\n"
         << "        <span class='badge badge-warning'>HOLD ACTIVE</span>\n"
         << "      </div>\n"
         << "      <p style='font-size:13px; color:#cbd5e1; margin-bottom:14px;'>This transfer exceeds the statutory $10,000 threshold. To prevent freezing your account, please enter the security OTP sent to your registered device:</p>\n"
         << "      \n"
         << "      <div style='background:#070a10; padding:12px; border-radius:8px; border:1px solid var(--border); margin-bottom:14px;'>\n"
         << "        <div style='font-size:12px; color:var(--text-muted);'>TEST SIMULATION OTP:</div>\n"
         << "        <div style='font-family:var(--font-mono); font-size:22px; font-weight:800; color:var(--success); letter-spacing:4px;'>849201</div>\n"
         << "      </div>\n"
         << "      \n"
         << "      <label>Enter 6-Digit OTP:</label>\n"
         << "      <input id='inputOtp' placeholder='849201' value='849201'>\n"
         << "      <label>Declared Transfer Purpose:</label>\n"
         << "      <select id='otpPurpose'>\n"
         << "        <option value='Verified Hospital Medical Emergency'>🏥 Medical Emergency / Hospital Bill</option>\n"
         << "        <option value='Commercial Real Estate Escrow'>🏢 Commercial Property Purchase</option>\n"
         << "        <option value='Authorized Corporate Payroll'>💼 Corporate Employee Payroll</option>\n"
         << "      </select>\n"
         << "      \n"
         << "      <div style='display:flex; gap:10px; margin-top:14px;'>\n"
         << "        <button class='btn btn-success' style='flex:1;' onclick='submitOtpVerification(true)'>✅ Verify &amp; Release Hold</button>\n"
         << "        <button class='btn btn-danger' style='flex:1;' onclick='submitOtpVerification(false)'>❌ Abort / Lock Account</button>\n"
         << "      </div>\n"
         << "    </div>\n"
         << "  </div>\n"
         << "  \n"
         << "  <!-- JAVASCRIPT LOGIC -->\n"
         << "  <script>\n"
         << "    // Initial C++ State Injected\n"
         << "    const systemState = " << stateJson << ";\n"
         << "    \n"
         << "    let currentUsername = 'alice';\n"
         << "    let pendingTransferObj = null;\n"
         << "    let isRegisterMode = false;\n"
         << "    \n"
         << "    let transactionsList = [\n"
         << "      { id: 'TXN-101', sender: 'Alice Sharma (ACC-789012)', recipient: 'Retail Grocery Mart', amount: 3000, type: 'Standard Domestic', time: '2026-09-24 14:20', status: 'CLEARED' },\n"
         << "      { id: 'TXN-102', sender: 'Alice Sharma (ACC-789012)', recipient: 'Vikram Malhotra (ACC-345678)', amount: 4500, type: 'Standard Domestic', time: '2026-09-24 16:45', status: 'CLEARED' },\n"
         << "      { id: 'TXN-103', sender: 'Alice Sharma (ACC-789012)', recipient: 'Offshore Asset Management (KY)', amount: 12000, type: 'High-Value Wire', time: '2026-09-24 19:10', status: 'FLAGGED' },\n"
         << "      { id: 'TXN-104', sender: 'Charlie Brown (ACC-901234)', recipient: 'Darknet-Crypto-Mixer', amount: 8500, type: 'Sanction Violation', time: '2026-09-24 21:05', status: 'CRITICAL_BLOCK' }\n"
         << "    ];\n"
         << "    \n"
         << "    let sarReportsList = [\n"
         << "      {\n"
         << "        id: 'SAR-2026-101',\n"
         << "        subject: 'Alice Sharma',\n"
         << "        account: 'ACC-789012',\n"
         << "        recipient: 'Offshore Asset Management (KY)',\n"
         << "        amount: 12000,\n"
         << "        violation: 'STATUTORY BSA THRESHOLD ($10,000)',\n"
         << "        reason: 'Single transfer of $12,000 exceeds statutory limit. Placed on Temporary Safety Hold.',\n"
         << "        action: 'Temporary Safety Hold Active. Awaiting Customer 2FA / Emergency Verification.',\n"
         << "        date: '2026-09-24 19:10 UTC',\n"
         << "        status: 'UNDER_AUDIT'\n"
         << "      },\n"
         << "      {\n"
         << "        id: 'SAR-2026-102',\n"
         << "        subject: 'Charlie Brown',\n"
         << "        account: 'ACC-901234',\n"
         << "        recipient: 'Darknet-Crypto-Mixer',\n"
         << "        amount: 8500,\n"
         << "        violation: 'OFAC FEDERAL SANCTIONS VIOLATION',\n"
         << "        reason: 'Matched against Global OFAC Specially Designated Nationals (SDN) Watchlist.',\n"
         << "        action: 'CRITICAL: Account Frozen under Executive Order 13694 &amp; FinCEN Notification.',\n"
         << "        date: '2026-09-24 21:05 UTC',\n"
         << "        status: 'CONFIRMED_FROZEN'\n"
         << "      }\n"
         << "    ];\n"
         << "    \n"
         << "    document.addEventListener('DOMContentLoaded', () => {\n"
         << "      refreshProfile();\n"
         << "      renderLedger();\n"
         << "      renderSARs();\n"
         << "    });\n"
         << "    \n"
         << "    function switchTab(tabId) {\n"
         << "      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));\n"
         << "      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));\n"
         << "      \n"
         << "      let btn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));\n"
         << "      if (btn) btn.classList.add('active');\n"
         << "      document.getElementById(tabId).classList.add('active');\n"
         << "    }\n"
         << "    \n"
         << "    function toggleAuthMode() {\n"
         << "      isRegisterMode = !isRegisterMode;\n"
         << "      document.getElementById('loginSection').style.display = isRegisterMode ? 'none' : 'block';\n"
         << "      document.getElementById('registerSection').style.display = isRegisterMode ? 'block' : 'none';\n"
         << "      document.getElementById('authToggleBtn').textContent = isRegisterMode ? 'Back to Login' : '+ Create New Account';\n"
         << "    }\n"
         << "    \n"
         << "    function quickLogin(u) {\n"
         << "      currentUsername = u;\n"
         << "      refreshProfile();\n"
         << "    }\n"
         << "    \n"
         << "    function handleLogin() {\n"
         << "      let u = document.getElementById('loginUser').value.trim();\n"
         << "      let userObj = systemState.users.find(x => x.username.toLowerCase() === u.toLowerCase());\n"
         << "      if (userObj) {\n"
         << "        currentUsername = userObj.username;\n"
         << "        refreshProfile();\n"
         << "        alert('Welcome back, ' + userObj.name + '!');\n"
         << "      } else {\n"
         << "        alert('User not found. You can click \"+ Create New Account\" to register instantly!');\n"
         << "      }\n"
         << "    }\n"
         << "    \n"
         << "    function handleRegister() {\n"
         << "      let name = document.getElementById('regName').value.trim();\n"
         << "      let u = document.getElementById('regUser').value.trim();\n"
         << "      let p = document.getElementById('regPass').value.trim();\n"
         << "      let bal = parseFloat(document.getElementById('regBal').value);\n"
         << "      \n"
         << "      if (!name || !u || !p || isNaN(bal)) {\n"
         << "        alert('Please fill out all registration fields.');\n"
         << "        return;\n"
         << "      }\n"
         << "      \n"
         << "      let newAcc = 'ACC-' + Math.floor(100000 + Math.random() * 900000);\n"
         << "      let newUser = { username: u, name: name, account: newAcc, balance: bal, country: 'IN', status: 'ACTIVE' };\n"
         << "      systemState.users.push(newUser);\n"
         << "      currentUsername = u;\n"
         << "      \n"
         << "      toggleAuthMode();\n"
         << "      refreshProfile();\n"
         << "      alert('Account Successfully Created in C++ Memory! Account #: ' + newAcc);\n"
         << "    }\n"
         << "    \n"
         << "    function refreshProfile() {\n"
         << "      let u = systemState.users.find(x => x.username === currentUsername) || systemState.users[0];\n"
         << "      document.getElementById('dispName').textContent = u.name;\n"
         << "      document.getElementById('dispAcc').textContent = 'Account: ' + u.account + ' (' + u.country + ')';\n"
         << "      document.getElementById('dispBal').textContent = '$' + Number(u.balance).toLocaleString(undefined, {minimumFractionDigits: 2});\n"
         << "      \n"
         << "      let badge = document.getElementById('userStatusBadge');\n"
         << "      if (u.status === 'FROZEN') {\n"
         << "        badge.className = 'badge badge-danger'; badge.textContent = '🔒 HARD FROZEN';\n"
         << "      } else if (u.status === 'TEMPORARY_HOLD') {\n"
         << "        badge.className = 'badge badge-warning'; badge.textContent = '⚠️ TEMPORARY HOLD';\n"
         << "      } else {\n"
         << "        badge.className = 'badge badge-success'; badge.textContent = '🟢 ACTIVE';\n"
         << "      }\n"
         << "    }\n"
         << "    \n"
         << "    function updateRiskMeter(val) {\n"
         << "      let amt = parseFloat(val) || 0;\n"
         << "      let score = 15;\n"
         << "      if (amt >= 5000) score = 35;\n"
         << "      if (amt >= 10000) score = 75;\n"
         << "      if (amt >= 50000) score = 95;\n"
         << "      \n"
         << "      document.getElementById('riskScoreText').textContent = score + '%';\n"
         << "      document.getElementById('riskGaugeBar').style.width = score + '%';\n"
         << "      \n"
         << "      let lbl = document.getElementById('riskLabel');\n"
         << "      if (score >= 75) {\n"
         << "        lbl.textContent = 'CRITICAL: STATUTORY SAR REPORT REQUIRED';\n"
         << "        lbl.style.color = 'var(--danger)';\n"
         << "      } else if (score >= 35) {\n"
         << "        lbl.textContent = 'ELEVATED TRANSACTION VOLUME';\n"
         << "        lbl.style.color = 'var(--warning)';\n"
         << "      } else {\n"
         << "        lbl.textContent = 'NORMAL ROUTINE TRANSACTION';\n"
         << "        lbl.style.color = 'var(--success)';\n"
         << "      }\n"
         << "    }\n"
         << "    \n"
         << "    function executeTransfer() {\n"
         << "      let u = systemState.users.find(x => x.username === currentUsername);\n"
         << "      if (u.status === 'FROZEN') {\n"
         << "        alert('❌ TRANSACTION BLOCKED: Your account is FROZEN under Bank Secrecy Act Section 5318(g).');\n"
         << "        return;\n"
         << "      }\n"
         << "      \n"
         << "      let amt = parseFloat(document.getElementById('transferAmt').value);\n"
         << "      let recipient = document.getElementById('transferRecipient').value;\n"
         << "      \n"
         << "      if (isNaN(amt) || amt <= 0) { alert('Enter a valid amount'); return; }\n"
         << "      if (amt > u.balance) { alert('Insufficient account balance!'); return; }\n"
         << "      \n"
         << "      // 1. Check Sanctions Blacklist\n"
         << "      if (recipient.includes('Darknet') || recipient.includes('Tornado')) {\n"
         << "        u.status = 'FROZEN';\n"
         << "        refreshProfile();\n"
         << "        \n"
         << "        let repId = 'SAR-2026-' + (100 + sarReportsList.length + 1);\n"
         << "        sarReportsList.unshift({\n"
         << "          id: repId,\n"
         << "          subject: u.name,\n"
         << "          account: u.account,\n"
         << "          recipient: recipient,\n"
         << "          amount: amt,\n"
         << "          violation: 'OFAC FEDERAL SANCTIONS VIOLATION',\n"
         << "          reason: 'Attempted transfer to Blacklisted Crypto Mixer entity: ' + recipient,\n"
         << "          action: 'Account Frozen immediately. Filed with Federal Enforcement Network.',\n"
         << "          date: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',\n"
         << "          status: 'CONFIRMED_FROZEN'\n"
         << "        });\n"
         << "        \n"
         << "        transactionsList.unshift({\n"
         << "          id: 'TXN-' + Math.floor(1000 + Math.random()*9000),\n"
         << "          sender: u.name + ' (' + u.account + ')',\n"
         << "          recipient: recipient,\n"
         << "          amount: amt,\n"
         << "          type: 'Sanction Block',\n"
         << "          time: 'Just now',\n"
         << "          status: 'CRITICAL_BLOCK'\n"
         << "        });\n"
         << "        \n"
         << "        renderLedger();\n"
         << "        renderSARs();\n"
         << "        switchTab('tabAuditor');\n"
         << "        alert('🚫 SANCTIONS VIOLATION! Recipient is on Federal Watchlist. Transfer Blocked & Account Frozen!');\n"
         << "        return;\n"
         << "      }\n"
         << "      \n"
         << "      // 2. Check > $10,000 Threshold for Step-Up 2FA\n"
         << "      if (amt > 10000) {\n"
         << "        pendingTransferObj = { sender: u, amount: amt, recipient: recipient };\n"
         << "        u.status = 'TEMPORARY_HOLD';\n"
         << "        refreshProfile();\n"
         << "        document.getElementById('otpModal').classList.add('active');\n"
         << "        return;\n"
         << "      }\n"
         << "      \n"
         << "      // 3. Normal Transfer Cleared\n"
         << "      u.balance -= amt;\n"
         << "      refreshProfile();\n"
         << "      transactionsList.unshift({\n"
         << "        id: 'TXN-' + Math.floor(1000 + Math.random()*9000),\n"
         << "        sender: u.name + ' (' + u.account + ')',\n"
         << "        recipient: recipient,\n"
         << "        amount: amt,\n"
         << "        type: 'Standard Transfer',\n"
         << "        time: 'Just now',\n"
         << "        status: 'CLEARED'\n"
         << "      });\n"
         << "      renderLedger();\n"
         << "      alert('✅ Transfer Cleared: $' + amt.toLocaleString() + ' successfully sent to ' + recipient);\n"
         << "    }\n"
         << "    \n"
         << "    function submitOtpVerification(isApproved) {\n"
         << "      document.getElementById('otpModal').classList.remove('active');\n"
         << "      if (!pendingTransferObj) return;\n"
         << "      \n"
         << "      let u = pendingTransferObj.sender;\n"
         << "      let amt = pendingTransferObj.amount;\n"
         << "      let rec = pendingTransferObj.recipient;\n"
         << "      let purpose = document.getElementById('otpPurpose').value;\n"
         << "      let otpInput = document.getElementById('inputOtp').value.trim();\n"
         << "      \n"
         << "      if (isApproved && otpInput === '849201') {\n"
         << "        // Emergency Approved & Released!\n"
         << "        u.status = 'ACTIVE';\n"
         << "        u.balance -= amt;\n"
         << "        refreshProfile();\n"
         << "        \n"
         << "        transactionsList.unshift({\n"
         << "          id: 'TXN-' + Math.floor(1000 + Math.random()*9000),\n"
         << "          sender: u.name + ' (' + u.account + ')',\n"
         << "          recipient: rec,\n"
         << "          amount: amt,\n"
         << "          type: 'Verified Emergency Transfer',\n"
         << "          time: 'Just now',\n"
         << "          status: 'CLEARED_EXEMPTION'\n"
         << "        });\n"
         << "        renderLedger();\n"
         << "        alert('🎉 2FA OTP Verified! Emergency Purpose Logged: \"' + purpose + '\". Account released from hold and $' + amt.toLocaleString() + ' transferred successfully.');\n"
         << "      } else {\n"
         << "        // Failed / Aborted -> Hard SAR Filing & Freeze\n"
         << "        u.status = 'FROZEN';\n"
         << "        refreshProfile();\n"
         << "        \n"
         << "        let repId = 'SAR-2026-' + (100 + sarReportsList.length + 1);\n"
         << "        sarReportsList.unshift({\n"
         << "          id: repId,\n"
         << "          subject: u.name,\n"
         << "          account: u.account,\n"
         << "          recipient: rec,\n"
         << "          amount: amt,\n"
         << "          violation: 'FAILED STEP-UP 2FA / POTENTIAL ACCOUNT TAKEOVER',\n"
         << "          reason: 'High-value transfer of $' + amt.toLocaleString() + ' failed security verification challenge.',\n"
         << "          action: 'Hard Freeze Confirmed. Account locked pending identity verification.',\n"
         << "          date: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',\n"
         << "          status: 'CONFIRMED_FROZEN'\n"
         << "        });\n"
         << "        renderSARs();\n"
         << "        switchTab('tabAuditor');\n"
         << "        alert('🚨 VERIFICATION FAILED! Account Hard-Frozen and Regulatory SAR filed in Tab 4.');\n"
         << "      }\n"
         << "      pendingTransferObj = null;\n"
         << "    }\n"
         << "    \n"
         << "    function simulateEmergencyFlow() {\n"
         << "      switchTab('tabPortal');\n"
         << "      document.getElementById('transferAmt').value = '25000';\n"
         << "      updateRiskMeter(25000);\n"
         << "      alert('Now click \"Execute Transaction via OOPS Engine\" to see how the emergency OTP modal prevents freezing genuine customers!');\n"
         << "    }\n"
         << "    \n"
         << "    function renderLedger() {\n"
         << "      let tbody = document.getElementById('ledgerTableBody');\n"
         << "      tbody.innerHTML = '';\n"
         << "      transactionsList.forEach(t => {\n"
         << "        let statusBadge = (t.status === 'CLEARED' || t.status === 'CLEARED_EXEMPTION')\n"
         << "          ? '<span class=\"badge badge-success\">Cleared</span>'\n"
         << "          : ((t.status === 'FLAGGED') ? '<span class=\"badge badge-warning\">Hold</span>' : '<span class=\"badge badge-danger\">Blocked</span>');\n"
         << "        \n"
         << "        let row = document.createElement('tr');\n"
         << "        row.innerHTML = '<td><strong>' + t.id + '</strong></td>' +\n"
         << "                        '<td>' + t.sender + ' &rarr; ' + t.recipient + '</td>' +\n"
         << "                        '<td style=\"font-family:var(--font-mono); font-weight:700;\">$' + Number(t.amount).toLocaleString() + '.00</td>' +\n"
         << "                        '<td>' + t.type + '</td>' +\n"
         << "                        '<td>' + t.time + '</td>' +\n"
         << "                        '<td>' + statusBadge + '</td>';\n"
         << "        tbody.appendChild(row);\n"
         << "      });\n"
         << "    }\n"
         << "    \n"
         << "    function renderSARs() {\n"
         << "      let container = document.getElementById('sarReportCardsContainer');\n"
         << "      container.innerHTML = '';\n"
         << "      document.getElementById('sarCountBadge').textContent = sarReportsList.length + ' ACTIVE REPORTS';\n"
         << "      \n"
         << "      sarReportsList.forEach((rep, idx) => {\n"
         << "        let card = document.createElement('div');\n"
         << "        card.className = 'sar-card';\n"
         << "        \n"
         << "        let isFrozen = (rep.status === 'CONFIRMED_FROZEN');\n"
         << "        let statusTag = isFrozen \n"
         << "          ? '<span class=\"badge badge-danger\">CONFIRMED FROZEN</span>'\n"
         << "          : '<span class=\"badge badge-warning\">HOLD / PENDING AUDIT</span>';\n"
         << "        \n"
         << "        card.innerHTML = '<div class=\"sar-head\">' +\n"
         << "                         '  <span style=\"font-family:var(--font-mono); font-size:16px; font-weight:800; color:var(--danger);\">📑 ' + rep.id + '</span>' +\n"
         << "                         '  ' + statusTag +\n"
         << "                         '</div>' +\n"
         << "                         '<div class=\"sar-grid\">' +\n"
         << "                         '  <div><strong>Subject:</strong> ' + rep.subject + ' (' + rep.account + ')</div>' +\n"
         << "                         '  <div><strong>Flagged Amount:</strong> $' + Number(rep.amount).toLocaleString() + '.00</div>' +\n"
         << "                         '  <div><strong>Recipient:</strong> ' + rep.recipient + '</div>' +\n"
         << "                         '  <div><strong>Filing Timestamp:</strong> ' + rep.date + '</div>' +\n"
         << "                         '</div>' +\n"
         << "                         '<div class=\"sar-reason\"><strong>Reason for SAR:</strong> ' + rep.reason + '</div>' +\n"
         << "                         '<div class=\"sar-action\"><strong>Recommended Action:</strong> ' + rep.action + '</div>' +\n"
         << "                         '<div class=\"sar-btns\">' +\n"
         << "                         '  <button class=\"btn btn-success btn-sm\" onclick=\"unfreezeAccount(\\'' + rep.subject + '\\', ' + idx + ')\">🟢 Release Hold (Emergency Cleared)</button>' +\n"
         << "                         '  <button class=\"btn btn-danger btn-sm\" onclick=\"confirmHardFreeze(\\'' + rep.subject + '\\', ' + idx + ')\">🔴 Confirm Hard Freeze</button>' +\n"
         << "                         '  <button class=\"btn btn-secondary btn-sm\" onclick=\"downloadReportText(' + idx + ')\">📥 Download SAR (.txt)</button>' +\n"
         << "                         '</div>';\n"
         << "        container.appendChild(card);\n"
         << "      });\n"
         << "    }\n"
         << "    \n"
         << "    function unfreezeAccount(userName, idx) {\n"
         << "      let u = systemState.users.find(x => x.name.toLowerCase() === userName.toLowerCase() || x.username.toLowerCase() === userName.toLowerCase());\n"
         << "      if (u) { u.status = 'ACTIVE'; refreshProfile(); }\n"
         << "      sarReportsList[idx].status = 'CLEARED_EMERGENCY';\n"
         << "      sarReportsList[idx].action = '✅ Hold Released by Compliance Officer. Customer Verified.';\n"
         << "      renderSARs();\n"
         << "      alert('✅ Hold Released! Account for ' + userName + ' is now restored to ACTIVE status.');\n"
         << "    }\n"
         << "    \n"
         << "    function confirmHardFreeze(userName, idx) {\n"
         << "      let u = systemState.users.find(x => x.name.toLowerCase() === userName.toLowerCase() || x.username.toLowerCase() === userName.toLowerCase());\n"
         << "      if (u) { u.status = 'FROZEN'; refreshProfile(); }\n"
         << "      sarReportsList[idx].status = 'CONFIRMED_FROZEN';\n"
         << "      sarReportsList[idx].action = '🔒 Confirmed Hard Freeze under BSA Section 5318(g). Asset locked.';\n"
         << "      renderSARs();\n"
         << "      alert('🔒 Hard Freeze Confirmed! Account assets locked down.');\n"
         << "    }\n"
         << "    \n"
         << "    function downloadReportText(idx) {\n"
         << "      let rep = sarReportsList[idx];\n"
         << "      let text = 'FINANCIAL CRIMES ENFORCEMENT NETWORK (FinCEN)\\n' +\n"
         << "                 'SUSPICIOUS ACTIVITY REPORT (FORM 111)\\n' +\n"
         << "                 '--------------------------------------------------------\\n' +\n"
         << "                 'Filing Reference: ' + rep.id + '\\n' +\n"
         << "                 'Subject Entity: ' + rep.subject + ' (' + rep.account + ')\\n' +\n"
         << "                 'Flagged Amount: $' + Number(rep.amount).toLocaleString() + '.00 USD\\n' +\n"
         << "                 'Recipient Target: ' + rep.recipient + '\\n' +\n"
         << "                 'Violation: ' + rep.violation + '\\n' +\n"
         << "                 'Date: ' + rep.date + '\\n\\n' +\n"
         << "                 'NARRATIVE JUSTIFICATION:\\n' +\n"
         << "                 rep.reason + '\\n\\n' +\n"
         << "                 'REGULATORY ACTION TAKEN:\\n' +\n"
         << "                 rep.action + '\\n' +\n"
         << "                 '--------------------------------------------------------\\n' +\n"
         << "                 'ELECTRONIC SEAL: SHA256: 7f9a8b2c4e1d3f0a9b8c7d6e5f4a3b2c\\n';\n"
         << "      \n"
         << "      let blob = new Blob([text], { type: 'text/plain' });\n"
         << "      let url = URL.createObjectURL(blob);\n"
         << "      let a = document.createElement('a');\n"
         << "      a.href = url;\n"
         << "      a.download = rep.id + '_FinCEN_SAR.txt';\n"
         << "      a.click();\n"
         << "      URL.revokeObjectURL(url);\n"
         << "    }\n"
         << "  </script>\n"
         << "</body>\n"
         << "</html>\n";

    return page.str();
}

// ----------------------------------------------------------------------------
// 7. WINSOCK2 MULTI-CLIENT WEB SERVER
// ----------------------------------------------------------------------------
int main() {
    WSADATA wsa;
    SOCKET server_fd, client_fd;
    sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "[-] WSAStartup failed. Error Code: " << WSAGetLastError() << endl;
        return 1;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        cerr << "[-] Socket creation failed." << endl;
        WSACleanup();
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(9090);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        cerr << "[-] Bind failed on port 9090." << endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    if (listen(server_fd, 10) == SOCKET_ERROR) {
        cerr << "[-] Listen failed." << endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    SARSystemManager manager;

    cout << "===================================================================\n";
    cout << "  Design & Implementation of Automated SAR Generation System (OOPS)\n";
    cout << "===================================================================\n";
    cout << "[+] Server running at http://localhost:9090\n";
    cout << "[+] Features Active:\n";
    cout << "    1. Multi-Customer Dataset & Dynamic Registration (User Entity)\n";
    cout << "    2. Real-Time Transaction Ledger (BaseTransaction Polymorphism)\n";
    cout << "    3. AML Rules, Sanctions Watchlist & Emergency OTP Step-Up\n";
    cout << "    4. SAR Reports, Compliance Override (Unfreeze) & .txt Download\n";
    cout << "===================================================================\n";

    while (true) {
        client_fd = accept(server_fd, (sockaddr*)&client_addr, &client_len);
        if (client_fd == INVALID_SOCKET) {
            continue;
        }

        char buffer[4096];
        int bytesRead = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            string response = buildCompleteWebPage(manager);
            send(client_fd, response.c_str(), (int)response.size(), 0);
        }

        closesocket(client_fd);
    }

    closesocket(server_fd);
    WSACleanup();
    return 0;
}
