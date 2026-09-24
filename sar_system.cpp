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

    string getUsername() const { return username; }
    string getFullName() const { return fullName; }
    string getAccountNumber() const { return accountNumber; }
    double getBalance() const { return accountBalance; }
    string getCountry() const { return country; }
    AccountStatus getStatus() const { return status; }

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

// Derived Class 1: Standard Normal Transaction (Inheritance)
class NormalTransaction : public BaseTransaction {
public:
    NormalTransaction(string id, string from, string to, double amt, string time, string ctry = "US")
        : BaseTransaction(id, from, to, amt, time, ctry) {}

    bool isSuspicious() const override { return false; }
    double calculateRiskScore() const override { return 15.0; }
    string getRiskCategory() const override { return "Normal / Verified"; }
    string getTransactionType() const override { return "Standard Domestic Clearing"; }
};

// Derived Class 2: High-Value Transaction (Polymorphism)
class HighValueTransaction : public BaseTransaction {
public:
    HighValueTransaction(string id, string from, string to, double amt, string time, string ctry = "US")
        : BaseTransaction(id, from, to, amt, time, ctry) {}

    bool isSuspicious() const override { return (amount > 10000.0); }
    double calculateRiskScore() const override {
        double score = 40.0;
        if (amount > 10000.0) score += 35.0;
        if (amount > 50000.0) score += 20.0;
        return min(100.0, score);
    }
    string getRiskCategory() const override {
        return (amount > 10000.0) ? "ELEVATED (BSA CTR / SAR REQUIRED)" : "MODERATE";
    }
    string getTransactionType() const override { return "High-Value Commercial Wire"; }
};

// Derived Class 3: Sanctioned / Blacklisted Entity Transfer (Polymorphism)
class SanctionedTransaction : public BaseTransaction {
private:
    string matchedWatchlistEntity;

public:
    SanctionedTransaction(string id, string from, string to, double amt, string time, string matchedEntity)
        : BaseTransaction(id, from, to, amt, time, "GLOBAL_WATCHLIST"), matchedWatchlistEntity(matchedEntity) {}

    bool isSuspicious() const override { return true; }
    double calculateRiskScore() const override { return 99.0; }
    string getRiskCategory() const override { return "CRITICAL: OFAC SANCTIONS HIT"; }
    string getTransactionType() const override { return "Blacklisted Entity Direct Transfer"; }
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
    string complianceStatus;

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
        // Multi-Customer Dataset
        users.emplace("alice", User("alice", "1234", "Alice Sharma", "ACC-789012", 24500.0, "IN"));
        users.emplace("vikram", User("vikram", "1234", "Vikram Malhotra", "ACC-345678", 45000.0, "IN"));
        users.emplace("charlie", User("charlie", "1234", "Charlie Brown", "ACC-901234", 150000.0, "US"));
        users.emplace("diana", User("diana", "1234", "Diana Prince", "ACC-567890", 500000.0, "GB"));

        // Historical Transactions
        transactions.push_back(make_shared<NormalTransaction>("TXN-101", "Alice Sharma (ACC-789012)", "Retail Grocery Mart", 3000.0, "2026-09-24 14:20", "IN"));
        transactions.push_back(make_shared<NormalTransaction>("TXN-102", "Alice Sharma (ACC-789012)", "Vikram Malhotra (ACC-345678)", 4500.0, "2026-09-24 16:45", "IN"));
        transactions.push_back(make_shared<HighValueTransaction>("TXN-103", "Alice Sharma (ACC-789012)", "Offshore Asset Management", 12000.0, "2026-09-24 19:10", "KY"));
        transactions.push_back(make_shared<SanctionedTransaction>("TXN-104", "Charlie Brown (ACC-901234)", "Darknet-Crypto-Mixer", 8500.0, "2026-09-24 21:05", "Darknet-Crypto-Mixer"));

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
// 6. MODERN BLUE BANKING UI WITH TOAST NOTIFICATIONS (NO BROWSER POPUPS!)
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
         << "      --bg-main: #060b14;\n"
         << "      --bg-card: #0c1527;\n"
         << "      --bg-card-sub: #101d36;\n"
         << "      --border: #1a2c4e;\n"
         << "      --border-blue: #0284c7;\n"
         << "      --text-main: #f0f6fc;\n"
         << "      --text-muted: #8ba2c4;\n"
         << "      --blue-glow: #38bdf8;\n"
         << "      --blue-primary: #0284c7;\n"
         << "      --blue-hover: #0369a1;\n"
         << "      --blue-card: #132342;\n"
         << "      --danger: #ef4444;\n"
         << "      --danger-bg: #2d0b13;\n"
         << "      --warning: #f59e0b;\n"
         << "      --success: #10b981;\n"
         << "      --font-sans: 'Plus Jakarta Sans', sans-serif;\n"
         << "      --font-mono: 'JetBrains Mono', monospace;\n"
         << "    }\n"
         << "    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
         << "    body { background: var(--bg-main); color: var(--text-main); font-family: var(--font-sans); padding: 24px; min-height: 100vh; overflow-x: hidden; }\n"
         << "    .container { max-width: 1120px; margin: 0 auto; }\n"
         << "    \n"
         << "    /* Header Bar */\n"
         << "    .navbar { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 22px; }\n"
         << "    .brand-title { font-size: 22px; font-weight: 800; color: #38bdf8; display: flex; align-items: center; gap: 10px; letter-spacing: -0.02em; }\n"
         << "    .badge-cpp { background: #172554; color: #93c5fd; font-family: var(--font-mono); font-size: 11px; padding: 3px 9px; border-radius: 6px; border: 1px solid #1e40af; font-weight: 700; }\n"
         << "    .live-status { display: flex; align-items: center; gap: 10px; background: #0c1527; padding: 8px 16px; border-radius: 30px; border: 1px solid var(--border); font-size: 13px; }\n"
         << "    .dot { width: 9px; height: 9px; background: var(--blue-glow); border-radius: 50%; box-shadow: 0 0 10px var(--blue-glow); animation: pulse 1.8s infinite; }\n"
         << "    @keyframes pulse { 0%,100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.85); } }\n"
         << "    \n"
         << "    /* 4 Navigation Tabs */\n"
         << "    .tab-bar { display: flex; gap: 8px; background: #09101f; padding: 6px; border-radius: 14px; border: 1px solid var(--border); margin-bottom: 24px; }\n"
         << "    .tab-btn { flex: 1; padding: 13px 16px; background: transparent; border: none; color: var(--text-muted); font-size: 14px; font-weight: 700; cursor: pointer; border-radius: 10px; transition: all 0.2s; text-align: center; display: flex; align-items: center; justify-content: center; gap: 8px; }\n"
         << "    .tab-btn:hover { color: #fff; background: #132038; }\n"
         << "    .tab-btn.active { background: linear-gradient(135deg, #0284c7, #0369a1); color: #fff; box-shadow: 0 4px 14px rgba(2, 132, 199, 0.45); }\n"
         << "    \n"
         << "    /* Tab Contents */\n"
         << "    .tab-pane { display: none; background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 28px; animation: fadeIn 0.25s ease; }\n"
         << "    .tab-pane.active { display: block; }\n"
         << "    @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }\n"
         << "    \n"
         << "    /* Grid Layouts & Cards */\n"
         << "    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }\n"
         << "    @media (max-width: 880px) { .grid-2 { grid-template-columns: 1fr; } }\n"
         << "    .card-box { background: var(--bg-card-sub); border: 1px solid var(--border); border-radius: 12px; padding: 22px; margin-bottom: 16px; }\n"
         << "    .card-title { font-size: 15px; font-weight: 800; color: #e2e8f0; margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; letter-spacing: -0.01em; }\n"
         << "    \n"
         << "    /* Form Controls */\n"
         << "    label { display: block; font-size: 11px; font-weight: 700; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.05em; }\n"
         << "    input, select { width: 100%; padding: 12px 14px; background: #070d18; border: 1px solid var(--border); border-radius: 8px; color: #fff; font-size: 14px; margin-bottom: 14px; font-family: var(--font-sans); transition: border-color 0.2s, box-shadow 0.2s; }\n"
         << "    input:focus, select:focus { outline: none; border-color: var(--blue-glow); box-shadow: 0 0 10px rgba(56, 189, 248, 0.25); }\n"
         << "    \n"
         << "    /* Buttons */\n"
         << "    .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 12px 22px; border-radius: 9px; font-weight: 700; font-size: 14px; cursor: pointer; border: none; transition: all 0.2s; font-family: var(--font-sans); }\n"
         << "    .btn-primary { background: linear-gradient(135deg, #0284c7, #026597); color: #fff; box-shadow: 0 2px 10px rgba(2, 132, 199, 0.3); }\n"
         << "    .btn-primary:hover { background: linear-gradient(135deg, #0369a1, #075985); transform: translateY(-1px); }\n"
         << "    .btn-success { background: linear-gradient(135deg, #059669, #047857); color: #fff; }\n"
         << "    .btn-success:hover { background: #047857; }\n"
         << "    .btn-danger { background: linear-gradient(135deg, #dc2626, #b91c1c); color: #fff; box-shadow: 0 2px 10px rgba(220, 38, 38, 0.3); }\n"
         << "    .btn-danger:hover { background: #b91c1c; }\n"
         << "    .btn-secondary { background: #132342; color: #93c5fd; border: 1px solid #1e3a8a; }\n"
         << "    .btn-secondary:hover { background: #1b315b; color: #fff; }\n"
         << "    .btn-block { width: 100%; }\n"
         << "    .btn-sm { padding: 7px 14px; font-size: 12px; border-radius: 7px; }\n"
         << "    \n"
         << "    /* Badges */\n"
         << "    .badge { padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 800; font-family: var(--font-mono); display: inline-block; }\n"
         << "    .badge-success { background: #082f49; color: #38bdf8; border: 1px solid #0284c7; }\n"
         << "    .badge-warning { background: #451a03; color: #fbbf24; border: 1px solid #b45309; }\n"
         << "    .badge-danger { background: #450a0a; color: #fca5a5; border: 1px solid #ef4444; box-shadow: 0 0 8px rgba(239, 68, 68, 0.4); }\n"
         << "    .badge-blue { background: #172554; color: #bfdbfe; border: 1px solid #1d4ed8; }\n"
         << "    \n"
         << "    /* Table */\n"
         << "    table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }\n"
         << "    th { background: #070d18; padding: 12px 14px; color: var(--text-muted); font-size: 11px; text-transform: uppercase; font-weight: 700; border-bottom: 1px solid var(--border); letter-spacing: 0.05em; }\n"
         << "    td { padding: 13px 14px; border-bottom: 1px solid #14223d; color: #cbd5e1; }\n"
         << "    tr:hover td { background: #0e1a31; }\n"
         << "    \n"
         << "    /* Quick User Chips */\n"
         << "    .quick-users { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 18px; }\n"
         << "    .user-chip { background: #080f1d; border: 1px solid #1b2e50; padding: 10px 14px; border-radius: 9px; cursor: pointer; font-size: 13px; transition: all 0.2s; color: #cbd5e1; display: flex; justify-content: space-between; align-items: center; }\n"
         << "    .user-chip:hover { border-color: var(--blue-glow); background: #101e38; transform: translateY(-1px); }\n"
         << "    .user-chip strong { color: #38bdf8; }\n"
         << "    \n"
         << "    /* Balance Showcase */\n"
         << "    .balance-box { background: linear-gradient(135deg, #091a33, #0c2347); border: 1px solid #1d4ed8; padding: 20px; border-radius: 12px; margin-bottom: 18px; box-shadow: 0 4px 20px rgba(2, 132, 199, 0.15); }\n"
         << "    .balance-val { font-size: 30px; font-weight: 800; font-family: var(--font-mono); color: #38bdf8; text-shadow: 0 0 15px rgba(56, 189, 248, 0.4); margin-top: 4px; }\n"
         << "    \n"
         << "    /* Risk Speedometer */\n"
         << "    .gauge-container { background: #070d18; border: 1px solid var(--border); border-radius: 14px; padding: 22px; text-align: center; margin-bottom: 22px; }\n"
         << "    .gauge-track { height: 18px; background: #0f1c33; border-radius: 10px; overflow: hidden; margin: 14px 0; border: 1px solid #1a2f54; }\n"
         << "    .gauge-fill { height: 100%; width: 15%; background: linear-gradient(90deg, #38bdf8, #0284c7, #f59e0b, #ef4444); transition: width 0.4s ease; border-radius: 10px; }\n"
         << "    .gauge-score { font-family: var(--font-mono); font-size: 34px; font-weight: 800; color: #fff; }\n"
         << "    \n"
         << "    /* Floating Toast Notification Center */\n"
         << "    #toastContainer { position: fixed; top: 24px; right: 24px; z-index: 10000; display: flex; flex-direction: column; gap: 12px; max-width: 420px; width: 100%; pointer-events: none; }\n"
         << "    .toast-card { pointer-events: auto; background: #091322; border-radius: 12px; padding: 16px 18px; border-left: 5px solid var(--blue-primary); border-top: 1px solid #1a2d4f; border-right: 1px solid #1a2d4f; border-bottom: 1px solid #1a2d4f; box-shadow: 0 10px 30px rgba(0,0,0,0.6); display: flex; gap: 12px; align-items: flex-start; animation: slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1); transition: opacity 0.3s, transform 0.3s; }\n"
         << "    .toast-card.danger { border-left-color: var(--danger); background: #1c0a10; border-color: #521521; box-shadow: 0 0 20px rgba(239, 68, 68, 0.35); }\n"
         << "    .toast-card.success { border-left-color: var(--blue-glow); background: #081829; border-color: #133a61; }\n"
         << "    @keyframes slideIn { from { opacity: 0; transform: translateX(60px); } to { opacity: 1; transform: translateX(0); } }\n"
         << "    .toast-icon { font-size: 20px; }\n"
         << "    .toast-content { flex: 1; }\n"
         << "    .toast-title { font-size: 14px; font-weight: 800; color: #fff; margin-bottom: 2px; }\n"
         << "    .toast-desc { font-size: 13px; color: var(--text-muted); line-height: 1.4; }\n"
         << "    .toast-close { background: none; border: none; color: #64748b; font-size: 16px; cursor: pointer; padding: 0 4px; }\n"
         << "    .toast-close:hover { color: #fff; }\n"
         << "    \n"
         << "    /* Modals */\n"
         << "    .modal { display: none; position: fixed; inset: 0; background: rgba(3, 7, 18, 0.88); backdrop-filter: blur(5px); z-index: 9999; align-items: center; justify-content: center; padding: 20px; }\n"
         << "    .modal.active { display: flex; }\n"
         << "    .modal-box { background: #0c1629; border: 1px solid #1f3763; border-radius: 16px; width: 100%; max-width: 580px; padding: 28px; box-shadow: 0 20px 50px rgba(0,0,0,0.8); }\n"
         << "    \n"
         << "    /* SAR Cards */\n"
         << "    .sar-card { background: #091120; border: 1px solid #7f1d1d; border-left: 6px solid var(--danger); border-radius: 12px; padding: 22px; margin-bottom: 18px; }\n"
         << "    .sar-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }\n"
         << "    .sar-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 13px; color: #cbd5e1; margin-bottom: 14px; }\n"
         << "    .sar-reason { background: #18263f; border: 1px solid #233b66; color: #93c5fd; padding: 12px; border-radius: 8px; font-size: 13px; margin-bottom: 10px; }\n"
         << "    .sar-action { background: #2b0b14; border: 1px solid #7f1d1d; color: #fecdd3; padding: 12px; border-radius: 8px; font-size: 13px; margin-bottom: 14px; font-weight: 700; }\n"
         << "    .sar-btns { display: flex; gap: 10px; flex-wrap: wrap; }\n"
         << "  </style>\n"
         << "</head>\n"
         << "<body>\n"
         << "  <!-- Toast Notification Mount -->\n"
         << "  <div id='toastContainer'></div>\n"
         << "  \n"
         << "  <div class='container'>\n"
         << "    <!-- NAVBAR -->\n"
         << "    <header class='navbar'>\n"
         << "      <div>\n"
         << "        <div class='brand-title'>🛡️ Automated SAR Generation System <span class='badge-cpp'>C++17 OOPS</span></div>\n"
         << "        <div style='color: var(--text-muted); font-size: 13px; margin-top: 4px;'>Financial Crime AML Intelligence &bull; Winsock2 Port 9090</div>\n"
         << "      </div>\n"
         << "      <div class='live-status'>\n"
         << "        <span class='dot'></span>\n"
         << "        <span style='color:#38bdf8; font-weight:700;'>C++ Core Active</span>\n"
         << "        <span style='color:var(--text-muted); font-family:var(--font-mono); margin-left:6px;'>BSA 31 U.S.C. 5318(g)</span>\n"
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
         << "    <!-- TAB 1: CUSTOMER PORTAL -->\n"
         << "    <div id='tabPortal' class='tab-pane active'>\n"
         << "      <div class='grid-2'>\n"
         << "        <!-- Left Column: User Authentication -->\n"
         << "        <div class='card-box'>\n"
         << "          <div class='card-title'>\n"
         << "            <span>Authentication (User Entity)</span>\n"
         << "            <button class='btn btn-secondary btn-sm' onclick='toggleAuthMode()' id='authToggleBtn'>+ Create New Account</button>\n"
         << "          </div>\n"
         << "          \n"
         << "          <div style='font-size:11px; font-weight:700; color:var(--text-muted); margin-bottom:8px; text-transform:uppercase;'>Switch Demo Account (1-Click):</div>\n"
         << "          <div class='quick-users'>\n"
         << "            <div class='user-chip' onclick=\"quickLogin('alice')\"><span>👩 <strong>Alice</strong></span><span style='font-family:var(--font-mono); font-size:11px;'>$24.5k</span></div>\n"
         << "            <div class='user-chip' onclick=\"quickLogin('vikram')\"><span>👨 <strong>Vikram</strong></span><span style='font-family:var(--font-mono); font-size:11px;'>$45k</span></div>\n"
         << "            <div class='user-chip' onclick=\"quickLogin('charlie')\"><span>🏢 <strong>Charlie</strong></span><span style='font-family:var(--font-mono); font-size:11px;'>$150k</span></div>\n"
         << "            <div class='user-chip' onclick=\"quickLogin('diana')\"><span>💎 <strong>Diana</strong></span><span style='font-family:var(--font-mono); font-size:11px;'>$500k</span></div>\n"
         << "          </div>\n"
         << "          \n"
         << "          <div id='loginSection'>\n"
         << "            <label>Username:</label>\n"
         << "            <input id='loginUser' placeholder='e.g. alice' value='alice'>\n"
         << "            <label>Password:</label>\n"
         << "            <input id='loginPass' type='password' placeholder='e.g. 1234' value='1234'>\n"
         << "            <button class='btn btn-primary btn-block' onclick='handleLogin()'>🔑 Login to Account</button>\n"
         << "          </div>\n"
         << "          \n"
         << "          <div id='registerSection' style='display:none;'>\n"
         << "            <label>Full Name:</label>\n"
         << "            <input id='regName' placeholder='e.g. Rohit Verma'>\n"
         << "            <label>Username:</label>\n"
         << "            <input id='regUser' placeholder='e.g. rohit'>\n"
         << "            <label>Password:</label>\n"
         << "            <input id='regPass' type='password' placeholder='••••••••'>\n"
         << "            <label>Initial Opening Balance ($):</label>\n"
         << "            <input id='regBal' type='number' placeholder='10000'>\n"
         << "            <button class='btn btn-primary btn-block' onclick='handleRegister()'>✨ Instantiate C++ Account Object</button>\n"
         << "          </div>\n"
         << "        </div>\n"
         << "        \n"
         << "        <!-- Right Column: Profile & Fund Transfer -->\n"
         << "        <div class='card-box'>\n"
         << "          <div class='card-title'>\n"
         << "            <span>Active Customer Profile</span>\n"
         << "            <span id='userStatusBadge' class='badge badge-success'>ACTIVE</span>\n"
         << "          </div>\n"
         << "          \n"
         << "          <div id='profileDisplay'>\n"
         << "            <div style='font-size:22px; font-weight:800; color:#fff;' id='dispName'>Alice Sharma</div>\n"
         << "            <div style='font-family:var(--font-mono); color:var(--text-muted); font-size:13px; margin:4px 0 16px 0;' id='dispAcc'>Account: ACC-789012 (IN)</div>\n"
         << "            \n"
         << "            <div class='balance-box'>\n"
         << "              <div style='font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase;'>Available Liquidity</div>\n"
         << "              <div class='balance-val' id='dispBal'>$24,500.00</div>\n"
         << "            </div>\n"
         << "            \n"
         << "            <div class='card-title'>Initiate Fund Transfer</div>\n"
         << "            <label>Transfer Amount ($ USD):</label>\n"
         << "            <input id='transferAmt' type='number' placeholder='e.g. 15000' value='12000' oninput='updateRiskMeter(this.value)'>\n"
         << "            <label>Select Recipient Target:</label>\n"
         << "            <select id='transferRecipient'>\n"
         << "              <option value='Vikram Malhotra (ACC-345678)'>Vikram Malhotra (ACC-345678) - Domestic Verified</option>\n"
         << "              <option value='Charlie Brown (ACC-901234)'>Charlie Brown (ACC-901234) - Domestic Verified</option>\n"
         << "              <option value='Diana Prince (ACC-567890)'>Diana Prince (ACC-567890) - Domestic Verified</option>\n"
         << "              <option value='Offshore Asset Management (KY)'>Offshore Asset Management (Cayman Islands)</option>\n"
         << "              <option value='Darknet-Crypto-Mixer'>Darknet-Crypto-Mixer (⚠️ Sanctions Blacklist Target)</option>\n"
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
         << "        <span>Audit Ledger (BaseTransaction Polymorphism)</span>\n"
         << "        <span class='badge badge-blue'>Real-Time Stream</span>\n"
         << "      </div>\n"
         << "      <p style='color:var(--text-muted); font-size:13px; margin-bottom:18px;'>Every transfer is dynamically dispatched through C++ abstract base classes (`NormalTransaction`, `HighValueTransaction`, `SanctionedTransaction`).</p>\n"
         << "      \n"
         << "      <div style='overflow-x:auto;'>\n"
         << "        <table>\n"
         << "          <thead>\n"
         << "            <tr><th>Txn ID</th><th>Sender &rarr; Recipient</th><th>Amount</th><th>Category</th><th>Timestamp</th><th>Status</th></tr>\n"
         << "          </thead>\n"
         << "          <tbody id='ledgerTableBody'>\n"
         << "          </tbody>\n"
         << "        </table>\n"
         << "      </div>\n"
         << "    </div>\n"
         << "    \n"
         << "    <!-- TAB 3: AML COMPLIANCE RULES & OTP CHALLENGE -->\n"
         << "    <div id='tabRules' class='tab-pane'>\n"
         << "      <div class='grid-2'>\n"
         << "        <div>\n"
         << "          <div class='card-title'>Compliance Rules Engine (Analyst Entity)</div>\n"
         << "          <div class='card-box'>\n"
         << "            <div style='font-size:14px; font-weight:800; color:#38bdf8; margin-bottom:4px;'>Rule 1: Statutory BSA Threshold ($10,000)</div>\n"
         << "            <div style='font-size:13px; color:var(--text-muted); line-height:1.4;'>Amounts exceeding $10,000 trigger an automated Temporary Safety Hold and require 2FA OTP Step-Up verification.</div>\n"
         << "          </div>\n"
         << "          <div class='card-box'>\n"
         << "            <div style='font-size:14px; font-weight:800; color:var(--danger); margin-bottom:4px;'>Rule 2: OFAC / UN Sanctions Watchlist</div>\n"
         << "            <div style='font-size:13px; color:var(--text-muted); line-height:1.4;'>Immediate blocking &amp; SAR filing if recipient matches: <em>Darknet-Crypto-Mixer, Tornado-Cash-Vault, Lazarus-Hacker-Group</em>.</div>\n"
         << "          </div>\n"
         << "          <div class='card-box'>\n"
         << "            <div style='font-size:14px; font-weight:800; color:#34d399; margin-bottom:4px;'>Rule 3: Emergency Exemption Bypass</div>\n"
         << "            <div style='font-size:13px; color:var(--text-muted); line-height:1.4;'>Legitimate emergencies (Medical, Real Estate) are verified through OTP without freezing customer assets!</div>\n"
         << "          </div>\n"
         << "        </div>\n"
         << "        \n"
         << "        <div>\n"
         << "          <div class='gauge-container'>\n"
         << "            <div style='font-size:12px; font-weight:700; color:var(--text-muted);'>LIVE DYNAMIC RISK SPEEDOMETER</div>\n"
         << "            <div class='gauge-score' id='riskScoreText'>75%</div>\n"
         << "            <div class='gauge-track'>\n"
         << "              <div class='gauge-fill' id='riskGaugeBar' style='width: 75%;'></div>\n"
         << "            </div>\n"
         << "            <div id='riskLabel' style='font-size:13px; font-weight:800; color:var(--danger);'>CRITICAL: STATUTORY SAR REPORT REQUIRED</div>\n"
         << "          </div>\n"
         << "          \n"
         << "          <div class='card-box'>\n"
         << "            <div class='card-title'>Simulate Emergency Flow</div>\n"
         << "            <p style='font-size:13px; color:var(--text-muted); margin-bottom:14px;'>Simulate a customer executing a genuine $25,000 emergency medical transfer without facing a false-positive freeze:</p>\n"
         << "            <button class='btn btn-secondary btn-block' onclick='simulateEmergencyFlow()'>🏥 Test Emergency $25,000 Transfer</button>\n"
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
         << "      <p style='color:var(--text-muted); font-size:13px; margin-bottom:18px;'>Official regulatory filings under 31 U.S.C. 5318(g). Compliance officers can investigate, unfreeze genuine emergencies, or confirm hard freezes.</p>\n"
         << "      \n"
         << "      <div id='sarReportCardsContainer'>\n"
         << "      </div>\n"
         << "    </div>\n"
         << "  </div>\n"
         << "  \n"
         << "  <!-- EMERGENCY OTP STEP-UP MODAL -->\n"
         << "  <div id='otpModal' class='modal'>\n"
         << "    <div class='modal-box'>\n"
         << "      <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;'>\n"
         << "        <div style='font-size:18px; font-weight:800; color:#38bdf8;'>🚨 High-Value Step-Up 2FA Challenge</div>\n"
         << "        <span class='badge badge-warning'>SAFETY HOLD</span>\n"
         << "      </div>\n"
         << "      <p style='font-size:13px; color:#cbd5e1; margin-bottom:14px; line-height:1.4;'>This transfer exceeds the statutory $10,000 threshold. To verify this is not a fraudulent drain, please enter the security OTP:</p>\n"
         << "      \n"
         << "      <div style='background:#070d18; padding:14px; border-radius:10px; border:1px solid #1e3a8a; margin-bottom:14px; text-align:center;'>\n"
         << "        <div style='font-size:11px; font-weight:700; color:var(--text-muted);'>TEST DEMO OTP:</div>\n"
         << "        <div style='font-family:var(--font-mono); font-size:26px; font-weight:800; color:#38bdf8; letter-spacing:6px;'>849201</div>\n"
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
         << "      <div style='display:flex; gap:12px; margin-top:16px;'>\n"
         << "        <button class='btn btn-primary' style='flex:1;' onclick='submitOtpVerification(true)'>✅ Verify &amp; Release Hold</button>\n"
         << "        <button class='btn btn-danger' style='flex:1;' onclick='submitOtpVerification(false)'>❌ Abort &amp; Lock Account</button>\n"
         << "      </div>\n"
         << "    </div>\n"
         << "  </div>\n"
         << "  \n"
         << "  <!-- JAVASCRIPT LOGIC -->\n"
         << "  <script>\n"
         << "    const systemState = " << stateJson << ";\n"
         << "    \n"
         << "    let currentUsername = 'alice';\n"
         << "    let pendingTransferObj = null;\n"
         << "    let isRegisterMode = false;\n"
         << "    \n"
         << "    // Modern Toast Notification Function (Replaces annoying browser alert dialogs!)\n"
         << "    function showToast(title, message, type = 'info') {\n"
         << "      const container = document.getElementById('toastContainer');\n"
         << "      const toast = document.createElement('div');\n"
         << "      toast.className = 'toast-card ' + type;\n"
         << "      \n"
         << "      let icon = 'ℹ️';\n"
         << "      if (type === 'success') icon = '✅';\n"
         << "      if (type === 'danger') icon = '🚨';\n"
         << "      if (type === 'warning') icon = '⚠️';\n"
         << "      \n"
         << "      toast.innerHTML = '<div class=\"toast-icon\">' + icon + '</div>' +\n"
         << "                        '<div class=\"toast-content\">' +\n"
         << "                        '  <div class=\"toast-title\">' + title + '</div>' +\n"
         << "                        '  <div class=\"toast-desc\">' + message + '</div>' +\n"
         << "                        '</div>' +\n"
         << "                        '<button class=\"toast-close\" onclick=\"this.parentElement.remove()\">&times;</button>';\n"
         << "      \n"
         << "      container.appendChild(toast);\n"
         << "      \n"
         << "      setTimeout(() => {\n"
         << "        toast.style.opacity = '0';\n"
         << "        toast.style.transform = 'translateX(50px)';\n"
         << "        setTimeout(() => toast.remove(), 300);\n"
         << "      }, 4000);\n"
         << "    }\n"
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
         << "      showToast('System Online', 'Connected to C++ Winsock2 Engine on port 9090', 'info');\n"
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
         << "      let userObj = systemState.users.find(x => x.username.toLowerCase() === u.toLowerCase());\n"
         << "      showToast('Switched Account', 'Active profile set to ' + userObj.name, 'info');\n"
         << "    }\n"
         << "    \n"
         << "    function handleLogin() {\n"
         << "      let u = document.getElementById('loginUser').value.trim();\n"
         << "      let userObj = systemState.users.find(x => x.username.toLowerCase() === u.toLowerCase());\n"
         << "      if (userObj) {\n"
         << "        currentUsername = userObj.username;\n"
         << "        refreshProfile();\n"
         << "        showToast('Login Successful', 'Welcome back, ' + userObj.name + '!', 'success');\n"
         << "      } else {\n"
         << "        showToast('Authentication Failed', 'User not found. Try Alice or Vikram.', 'danger');\n"
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
         << "        showToast('Form Incomplete', 'Please fill out all registration fields.', 'warning');\n"
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
         << "      showToast('Account Created!', 'Instantiated User object in C++ memory. Account: ' + newAcc, 'success');\n"
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
         << "        lbl.style.color = 'var(--blue-glow)';\n"
         << "      }\n"
         << "    }\n"
         << "    \n"
         << "    function executeTransfer() {\n"
         << "      let u = systemState.users.find(x => x.username === currentUsername);\n"
         << "      if (u.status === 'FROZEN') {\n"
         << "        showToast('Transfer Blocked', 'Account is FROZEN under Bank Secrecy Act Section 5318(g).', 'danger');\n"
         << "        return;\n"
         << "      }\n"
         << "      \n"
         << "      let amt = parseFloat(document.getElementById('transferAmt').value);\n"
         << "      let recipient = document.getElementById('transferRecipient').value;\n"
         << "      \n"
         << "      if (isNaN(amt) || amt <= 0) { showToast('Invalid Input', 'Enter a positive amount', 'warning'); return; }\n"
         << "      if (amt > u.balance) { showToast('Insufficient Funds', 'Transfer amount exceeds current balance.', 'warning'); return; }\n"
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
         << "        showToast('🚫 SANCTIONS VIOLATION', 'Recipient is on Federal Watchlist! Transfer Blocked & Account Frozen.', 'danger');\n"
         << "        return;\n"
         << "      }\n"
         << "      \n"
         << "      // 2. Check > $10,000 Threshold for Step-Up 2FA\n"
         << "      if (amt > 10000) {\n"
         << "        pendingTransferObj = { sender: u, amount: amt, recipient: recipient };\n"
         << "        u.status = 'TEMPORARY_HOLD';\n"
         << "        refreshProfile();\n"
         << "        document.getElementById('otpModal').classList.add('active');\n"
         << "        showToast('2FA Challenge', 'High-value transfer placed on temporary safety hold.', 'warning');\n"
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
         << "      showToast('Transfer Cleared', '$' + amt.toLocaleString() + ' sent to ' + recipient, 'success');\n"
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
         << "        showToast('Hold Released & Cleared', 'Emergency verified: \"' + purpose + '\". Funds transferred.', 'success');\n"
         << "      } else {\n"
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
         << "        showToast('🚨 Verification Failed', 'Account Hard-Frozen & Regulatory SAR filed in Tab 4.', 'danger');\n"
         << "      }\n"
         << "      pendingTransferObj = null;\n"
         << "    }\n"
         << "    \n"
         << "    function simulateEmergencyFlow() {\n"
         << "      switchTab('tabPortal');\n"
         << "      document.getElementById('transferAmt').value = '25000';\n"
         << "      updateRiskMeter(25000);\n"
         << "      showToast('Emergency Simulation', 'Amount set to $25,000. Click Execute Transaction to test 2FA!', 'info');\n"
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
         << "      showToast('Hold Released', 'Account for ' + userName + ' is now restored to ACTIVE status.', 'success');\n"
         << "    }\n"
         << "    \n"
         << "    function confirmHardFreeze(userName, idx) {\n"
         << "      let u = systemState.users.find(x => x.name.toLowerCase() === userName.toLowerCase() || x.username.toLowerCase() === userName.toLowerCase());\n"
         << "      if (u) { u.status = 'FROZEN'; refreshProfile(); }\n"
         << "      sarReportsList[idx].status = 'CONFIRMED_FROZEN';\n"
         << "      sarReportsList[idx].action = '🔒 Confirmed Hard Freeze under BSA Section 5318(g). Asset locked.';\n"
         << "      renderSARs();\n"
         << "      showToast('Hard Freeze Confirmed', 'Account assets locked down under BSA Section 5318(g).', 'danger');\n"
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
         << "      showToast('Downloaded SAR Filing', 'Saved ' + rep.id + '_FinCEN_SAR.txt to your device.', 'success');\n"
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
    cout << "[+] Modern Blue Banking UI Active (No Browser Dialogs!)\n";
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
