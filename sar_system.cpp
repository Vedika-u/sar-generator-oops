#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include <iomanip>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

// ============================================================================
// PROJECT: Design and Implementation of an Automated SAR Generation System Using OOPS
// CORE OOPS ENTITIES:
//   1. User (Class & Object, Encapsulation)
//   2. BaseTransaction / Derived Classes (Abstraction, Inheritance, Polymorphism)
//   3. Analyst (Rule Engine & Decision Logic)
//   4. SARReport (Structured Reporting Entity)
// ============================================================================

// ----------------------------------------------------------------------------
// 1. ENTITY: User (Demonstrates Class, Object, & Encapsulation)
// ----------------------------------------------------------------------------
class User {
private:
    string username;
    string password;
    string accountNumber;
    double accountBalance;

public:
    User(string u, string p, string acc, double bal)
        : username(u), password(p), accountNumber(acc), accountBalance(bal) {}

    bool authenticate(const string& u, const string& p) const {
        return (username == u && password == p);
    }

    string getUsername() const { return username; }
    string getAccountNumber() const { return accountNumber; }
    double getBalance() const { return accountBalance; }

    void deductBalance(double amt) { accountBalance -= amt; }
    void addBalance(double amt) { accountBalance += amt; }
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

public:
    BaseTransaction(string id, string from, string to, double amt, string time)
        : txnId(id), sender(from), recipient(to), amount(amt), timestamp(time) {}

    virtual ~BaseTransaction() = default;

    // Pure virtual functions (Abstraction)
    virtual bool isSuspicious() const = 0;
    virtual string getRiskCategory() const = 0;
    virtual string getTransactionType() const = 0;

    string getId() const { return txnId; }
    string getSender() const { return sender; }
    string getRecipient() const { return recipient; }
    double getAmount() const { return amount; }
    string getTimestamp() const { return timestamp; }
};

// Derived Class 1: Normal Transaction (Demonstrates Inheritance)
class NormalTransaction : public BaseTransaction {
public:
    NormalTransaction(string id, string from, string to, double amt, string time)
        : BaseTransaction(id, from, to, amt, time) {}

    bool isSuspicious() const override {
        return false;
    }

    string getRiskCategory() const override {
        return "Normal / Low Risk";
    }

    string getTransactionType() const override {
        return "Domestic Standard Transfer";
    }
};

// Derived Class 2: Suspicious Large Transaction (Demonstrates Polymorphism)
class SuspiciousTransaction : public BaseTransaction {
private:
    string triggerReason;

public:
    SuspiciousTransaction(string id, string from, string to, double amt, string time, string reason)
        : BaseTransaction(id, from, to, amt, time), triggerReason(reason) {}

    bool isSuspicious() const override {
        return true;
    }

    string getRiskCategory() const override {
        return "CRITICAL SUSPICIOUS (SAR REQUIRED)";
    }

    string getTransactionType() const override {
        return "High-Risk Flagged Transfer";
    }

    string getReason() const { return triggerReason; }
};

// ----------------------------------------------------------------------------
// 3. ENTITY: SARReport (Structured Suspicious Activity Report)
// ----------------------------------------------------------------------------
class SARReport {
private:
    string reportId;
    string subjectUser;
    string suspectAccount;
    double flaggedAmount;
    string detectionReason;
    string recommendedAction;
    string filingDate;

public:
    SARReport(string id, string user, string acc, double amt, string reason, string action, string date)
        : reportId(id), subjectUser(user), suspectAccount(acc), flaggedAmount(amt),
          detectionReason(reason), recommendedAction(action), filingDate(date) {}

    string getReportId() const { return reportId; }
    string getSubject() const { return subjectUser; }
    string getAccount() const { return suspectAccount; }
    double getAmount() const { return flaggedAmount; }
    string getReason() const { return detectionReason; }
    string getAction() const { return recommendedAction; }
    string getDate() const { return filingDate; }
};

// ----------------------------------------------------------------------------
// 4. ENTITY: Analyst (Rule-based Evaluation & Automated SAR Generator)
// ----------------------------------------------------------------------------
class Analyst {
public:
    static bool evaluateAmount(double amt) {
        // Core AML Rule: Statutory threshold of $10,000
        return (amt > 10000.0);
    }

    static shared_ptr<SARReport> generateSAR(int reportSeq, const string& user, const string& acc, double amt) {
        string repId = "SAR-2026-" + to_string(100 + reportSeq);
        string reason = "Large Transaction: Single transfer of $" + to_string((int)amt) + 
                        " exceeds the statutory threshold of $10,000.";
        string action = "Freeze Account & Verify Identity. Escalate to Financial Crimes Compliance Team.";
        string date = "2026-09-25 10:15:00 UTC";

        return make_shared<SARReport>(repId, user, acc, amt, reason, action, date);
    }
};

// ----------------------------------------------------------------------------
// 5. SYSTEM MANAGER: Coordinates Users, Transactions, and SAR Reports
// ----------------------------------------------------------------------------
class SARSystemManager {
private:
    vector<User> users;
    vector<shared_ptr<BaseTransaction>> transactions;
    vector<shared_ptr<SARReport>> sarReports;
    mutex mtx;

public:
    SARSystemManager() {
        // Pre-populate users
        users.emplace_back("alice", "1234", "ACC-789012", 24500.0);
        users.emplace_back("bob", "5678", "ACC-345678", 8500.0);

        // Pre-populate transactions (similar to original {3000, 4500, 12000})
        addTransaction(make_shared<NormalTransaction>("TXN-001", "Alice (ACC-789012)", "Retail Merchant", 3000.0, "2026-09-24 14:20"));
        addTransaction(make_shared<NormalTransaction>("TXN-002", "Alice (ACC-789012)", "Electric Utility", 4500.0, "2026-09-24 16:45"));
        addTransaction(make_shared<SuspiciousTransaction>("TXN-003", "Alice (ACC-789012)", "Unknown Offshore Entity", 12000.0, "2026-09-24 19:10", "Amount > $10,000 Threshold"));

        // Pre-populate initial SAR report for the $12,000 transfer
        sarReports.push_back(Analyst::generateSAR(1, "alice", "ACC-789012", 12000.0));
    }

    void addTransaction(shared_ptr<BaseTransaction> txn) {
        lock_guard<mutex> lock(mtx);
        transactions.push_back(txn);
    }

    void addSAR(shared_ptr<SARReport> report) {
        lock_guard<mutex> lock(mtx);
        sarReports.push_back(report);
    }

    string getPreviousTxnsHTML() {
        lock_guard<mutex> lock(mtx);
        stringstream ss;
        ss << "<div class='table-responsive'><table class='styled-table'>"
           << "<thead><tr><th>Txn ID</th><th>Sender &rarr; Recipient</th><th>Amount</th><th>Type / Status</th><th>Timestamp</th></tr></thead><tbody>";

        for (const auto& t : transactions) {
            string badge = t->isSuspicious() 
                ? "<span class='badge badge-danger'>Flagged: Suspicious</span>" 
                : "<span class='badge badge-success'>Normal</span>";

            ss << "<tr>"
               << "<td><strong>" << t->getId() << "</strong></td>"
               << "<td>" << t->getSender() << " &rarr; " << t->getRecipient() << "</td>"
               << "<td>$" << fixed << setprecision(2) << t->getAmount() << "</td>"
               << "<td>" << badge << "</td>"
               << "<td>" << t->getTimestamp() << "</td>"
               << "</tr>";
        }
        ss << "</tbody></table></div>";
        return ss.str();
    }

    string getSarReportsHTML() {
        lock_guard<mutex> lock(mtx);
        if (sarReports.empty()) {
            return "<div class='alert-info'>No SAR reports generated yet. Normal banking transactions active.</div>";
        }

        stringstream ss;
        for (const auto& rep : sarReports) {
            ss << "<div class='sar-card'>"
               << "  <div class='sar-header'>"
               << "    <span class='sar-id'>📑 " << rep->getReportId() << "</span>"
               << "    <span class='badge badge-danger'>STATUS: REGULATORY AUDIT REQUIRED</span>"
               << "  </div>"
               << "  <div class='sar-grid'>"
               << "    <div><strong>Subject / Suspect:</strong> " << rep->getSubject() << " (" << rep->getAccount() << ")</div>"
               << "    <div><strong>Flagged Amount:</strong> $" << fixed << setprecision(2) << rep->getAmount() << "</div>"
               << "    <div><strong>Filing Timestamp:</strong> " << rep->getDate() << "</div>"
               << "    <div><strong>Regulatory Rule:</strong> 31 U.S.C. 5318(g) Bank Secrecy Act</div>"
               << "  </div>"
               << "  <div class='sar-reason'><strong>Reason for SAR:</strong> " << rep->getReason() << "</div>"
               << "  <div class='sar-action'><strong>Recommended Action:</strong> " << rep->getAction() << "</div>"
               << "</div>";
        }
        return ss.str();
    }
};

// ----------------------------------------------------------------------------
// 6. HTML PAGE GENERATOR (Renders the 4 Switchable Tabs Interface)
// ----------------------------------------------------------------------------
string generateFullPage(SARSystemManager& mgr) {
    string prevTxnsTable = mgr.getPreviousTxnsHTML();
    string sarReportsCards = mgr.getSarReportsHTML();

    stringstream page;
    page << "HTTP/1.1 200 OK\r\n"
         << "Content-Type: text/html\r\n"
         << "Connection: close\r\n\r\n"
         << "<!DOCTYPE html>\n"
         << "<html lang='en'>\n"
         << "<head>\n"
         << "  <meta charset='UTF-8'>\n"
         << "  <title>Automated SAR Generation System Using OOPS</title>\n"
         << "  <style>\n"
         << "    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }\n"
         << "    body { background: #0f172a; color: #f8fafc; padding: 24px; }\n"
         << "    .container { max-width: 1000px; margin: 0 auto; }\n"
         << "    \n"
         << "    /* Header */\n"
         << "    .title-bar { text-align: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 2px solid #334155; }\n"
         << "    .title-bar h1 { color: #38bdf8; font-size: 26px; margin-bottom: 6px; }\n"
         << "    .title-bar p { color: #94a3b8; font-size: 14px; }\n"
         << "    \n"
         << "    /* 4 Navigation Tabs */\n"
         << "    .tab-nav { display: flex; gap: 8px; margin-bottom: 20px; background: #1e293b; padding: 6px; border-radius: 10px; border: 1px solid #334155; }\n"
         << "    .tab-btn { flex: 1; padding: 12px 14px; background: transparent; border: none; color: #94a3b8; font-size: 14px; font-weight: 600; cursor: pointer; border-radius: 8px; transition: all 0.2s; text-align: center; }\n"
         << "    .tab-btn:hover { color: #fff; background: #334155; }\n"
         << "    .tab-btn.active { background: #0284c7; color: #ffffff; box-shadow: 0 2px 8px rgba(2, 132, 199, 0.4); }\n"
         << "    \n"
         << "    /* Tab Content Boxes */\n"
         << "    .tab-content { display: none; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; }\n"
         << "    .tab-content.active { display: block; animation: fadeIn 0.3s ease; }\n"
         << "    @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }\n"
         << "    \n"
         << "    /* Inputs & Buttons */\n"
         << "    .form-group { margin-bottom: 16px; text-align: left; }\n"
         << "    label { display: block; font-size: 13px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; }\n"
         << "    input, select { width: 100%; padding: 12px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; font-size: 15px; margin-bottom: 10px; }\n"
         << "    input:focus { outline: none; border-color: #38bdf8; }\n"
         << "    .btn { padding: 12px 24px; border: none; border-radius: 6px; font-weight: 600; font-size: 14px; cursor: pointer; transition: background 0.2s; }\n"
         << "    .btn-primary { background: #22c55e; color: #fff; }\n"
         << "    .btn-primary:hover { background: #16a34a; }\n"
         << "    .btn-blue { background: #0284c7; color: #fff; }\n"
         << "    .btn-blue:hover { background: #0369a1; }\n"
         << "    .btn-block { width: 100%; }\n"
         << "    \n"
         << "    /* Result Boxes */\n"
         << "    .result-box { margin-top: 18px; padding: 16px; border-radius: 8px; font-size: 15px; font-weight: 500; display: none; }\n"
         << "    .result-success { background: #064e3b; border: 1px solid #059669; color: #6ee7b7; display: block; }\n"
         << "    .result-danger { background: #881337; border: 1px solid #be123c; color: #fecdd3; display: block; }\n"
         << "    .result-warning { background: #451a03; border: 1px solid #b45309; color: #fde68a; display: block; }\n"
         << "    \n"
         << "    /* Tables & Badges */\n"
         << "    .styled-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }\n"
         << "    .styled-table th { background: #0f172a; padding: 12px; color: #94a3b8; font-weight: 600; border-bottom: 2px solid #334155; }\n"
         << "    .styled-table td { padding: 12px; border-bottom: 1px solid #334155; color: #e2e8f0; }\n"
         << "    .badge { padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; display: inline-block; }\n"
         << "    .badge-success { background: #064e3b; color: #34d399; }\n"
         << "    .badge-danger { background: #881337; color: #fca5a5; }\n"
         << "    \n"
         << "    /* SAR Cards */\n"
         << "    .sar-card { background: #0f172a; border: 1px solid #be123c; border-left: 6px solid #e11d48; border-radius: 8px; padding: 18px; margin-bottom: 16px; }\n"
         << "    .sar-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }\n"
         << "    .sar-id { font-size: 17px; font-weight: bold; color: #f43f5e; }\n"
         << "    .sar-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 14px; color: #cbd5e1; margin-bottom: 12px; }\n"
         << "    .sar-reason { background: #1e293b; padding: 10px; border-radius: 6px; font-size: 13px; color: #fde047; margin-bottom: 8px; }\n"
         << "    .sar-action { background: #3b0764; border: 1px solid #7e22ce; padding: 10px; border-radius: 6px; font-size: 13px; color: #e9d5ff; font-weight: 600; }\n"
         << "    \n"
         << "    .footer { text-align: center; color: #64748b; font-size: 13px; margin-top: 24px; }\n"
         << "  </style>\n"
         << "</head>\n"
         << "<body>\n"
         << "  <div class='container'>\n"
         << "    <div class='title-bar'>\n"
         << "      <h1>Automated SAR Generation System Using OOPS</h1>\n"
         << "      <p>C++ Winsock2 Web Server &bull; Port 9090 &bull; Object-Oriented Financial Crime Compliance</p>\n"
         << "    </div>\n"
         << "    \n"
         << "    <!-- 4 TABS NAVIGATION -->\n"
         << "    <nav class='tab-nav'>\n"
         << "      <button class='tab-btn active' onclick=\"switchTab('tabUser')\">👤 1. Customer Login</button>\n"
         << "      <button class='tab-btn' onclick=\"switchTab('tabTxns')\">💳 2. Transaction History</button>\n"
         << "      <button class='tab-btn' onclick=\"switchTab('tabAnalyst')\">🔍 3. AML Analyst & Rules</button>\n"
         << "      <button class='tab-btn' onclick=\"switchTab('tabSAR')\">📑 4. Generated SAR Reports</button>\n"
         << "    </nav>\n"
         << "    \n"
         << "    <!-- TAB 1: CUSTOMER LOGIN -->\n"
         << "    <div id='tabUser' class='tab-content active'>\n"
         << "      <h2 style='color:#38bdf8; margin-bottom:12px;'>Customer Authentication (User Entity)</h2>\n"
         << "      <p style='color:#94a3b8; font-size:14px; margin-bottom:18px;'>Demonstrates Class &amp; Object encapsulation. Test with sample accounts: <strong>alice / 1234</strong> or <strong>bob / 5678</strong>.</p>\n"
         << "      \n"
         << "      <div style='max-width: 400px; margin: 0 auto; text-align:center;'>\n"
         << "        <input id='user' placeholder='Username (e.g. alice)'>\n"
         << "        <input id='pass' type='password' placeholder='Password (e.g. 1234)'>\n"
         << "        <button class='btn btn-primary btn-block' onclick='login()'>Login to Account</button>\n"
         << "        <div id='loginBox' class='result-box'></div>\n"
         << "      </div>\n"
         << "    </div>\n"
         << "    \n"
         << "    <!-- TAB 2: TRANSACTIONS & PREVIOUS HISTORY -->\n"
         << "    <div id='tabTxns' class='tab-content'>\n"
         << "      <h2 style='color:#38bdf8; margin-bottom:12px;'>Previous Banking Transactions (Transaction Entity)</h2>\n"
         << "      <p style='color:#94a3b8; font-size:14px; margin-bottom:16px;'>Displays transaction telemetry stored in C++ objects (including initial $3,000, $4,500, and $12,000 records).</p>\n"
         << "      <div id='txnsContainer'>" << prevTxnsTable << "</div>\n"
         << "    </div>\n"
         << "    \n"
         << "    <!-- TAB 3: AML ANALYST & RULES ENGINE -->\n"
         << "    <div id='tabAnalyst' class='tab-content'>\n"
         << "      <h2 style='color:#38bdf8; margin-bottom:12px;'>Compliance Analyst Rules (Rule Engine Entity)</h2>\n"
         << "      <p style='color:#94a3b8; font-size:14px; margin-bottom:18px;'>Evaluates transactions against statutory Anti-Money Laundering (AML) thresholds using Polymorphism.</p>\n"
         << "      \n"
         << "      <div style='background:#0f172a; padding:16px; border-radius:8px; margin-bottom:20px; font-size:14px;'>\n"
         << "        <strong style='color:#facc15;'>Active Rule Set:</strong><br>\n"
         << "        &bull; <strong>Rule 1:</strong> Amount &gt; $10,000 &rarr; <span style='color:#f43f5e;'>Triggers Automated SAR Filing</span> (Reason: Large Transaction)<br>\n"
         << "        &bull; <strong>Rule 2:</strong> Amount &le; $10,000 &rarr; <span style='color:#34d399;'>Standard Domestic Clearance</span>\n"
         << "      </div>\n"
         << "      \n"
         << "      <div style='max-width: 500px; margin: 0 auto;'>\n"
         << "        <label>Enter Transaction Amount ($ USD):</label>\n"
         << "        <input id='amt' type='number' placeholder='Enter amount (e.g. 15000)'>\n"
         << "        <label>Recipient Account / Entity:</label>\n"
         << "        <input id='recipient' placeholder='e.g. Offshore Holdings Ltd' value='External Corporate Entity'>\n"
         << "        <button class='btn btn-blue btn-block' onclick='analyzeTransaction()'>🔍 Analyze Transaction with Analyst Rules</button>\n"
         << "        <div id='analystResult' class='result-box'></div>\n"
         << "      </div>\n"
         << "    </div>\n"
         << "    \n"
         << "    <!-- TAB 4: GENERATED SAR REPORTS -->\n"
         << "    <div id='tabSAR' class='tab-content'>\n"
         << "      <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;'>\n"
         << "        <h2 style='color:#38bdf8; margin:0;'>Structured SAR Reports (Report Entity)</h2>\n"
         << "        <button class='btn btn-primary' onclick=\"switchTab('tabAnalyst')\">+ Analyze New Transaction</button>\n"
         << "      </div>\n"
         << "      <p style='color:#94a3b8; font-size:14px; margin-bottom:18px;'>Official Suspicious Activity Reports generated automatically according to Bank Secrecy Act (BSA) compliance guidelines.</p>\n"
         << "      <div id='sarReportsContainer'>" << sarReportsCards << "</div>\n"
         << "    </div>\n"
         << "    \n"
         << "    <div class='footer'>\n"
         << "      Design and Implementation of an Automated SAR Generation System Using OOPS &bull; Built with C++ &amp; Winsock2\n"
         << "    </div>\n"
         << "  </div>\n"
         << "  \n"
         << "  <!-- JAVASCRIPT: 4-TAB SWITCHING & CLIENT LOGIC -->\n"
         << "  <script>\n"
         << "    function switchTab(tabId) {\n"
         << "      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));\n"
         << "      document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));\n"
         << "      \n"
         << "      let activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));\n"
         << "      if (activeBtn) activeBtn.classList.add('active');\n"
         << "      document.getElementById(tabId).classList.add('active');\n"
         << "    }\n"
         << "    \n"
         << "    function login() {\n"
         << "      let u = document.getElementById('user').value.trim();\n"
         << "      let p = document.getElementById('pass').value.trim();\n"
         << "      let box = document.getElementById('loginBox');\n"
         << "      \n"
         << "      if ((u === 'alice' && p === '1234') || (u === 'bob' && p === '5678')) {\n"
         << "        let accNum = (u === 'alice') ? 'ACC-789012' : 'ACC-345678';\n"
         << "        let balance = (u === 'alice') ? '$24,500.00' : '$8,500.00';\n"
         << "        \n"
         << "        box.className = 'result-box result-success';\n"
         << "        box.innerHTML = '<strong>Login Successful!</strong><br><br>' +\n"
         << "                        'Welcome, <strong>' + u.toUpperCase() + '</strong><br>' +\n"
         << "                        'Account Number: <strong>' + accNum + '</strong><br>' +\n"
         << "                        'Available Balance: <strong>' + balance + '</strong><br><br>' +\n"
         << "                        '<button class=\"btn btn-blue\" onclick=\"switchTab(\\'tabTxns\\')\">View Transaction History &rarr;</button> ' +\n"
         << "                        '<button class=\"btn btn-primary\" onclick=\"switchTab(\\'tabAnalyst\\')\">Analyze New Transfer &rarr;</button>';\n"
         << "      } else {\n"
         << "        box.className = 'result-box result-danger';\n"
         << "        box.innerHTML = '<strong>Invalid Login!</strong><br>Use username <em>alice</em> (pass: 1234) or <em>bob</em> (pass: 5678).';\n"
         << "      }\n"
         << "    }\n"
         << "    \n"
         << "    let sarReportCount = 1;\n"
         << "    \n"
         << "    function analyzeTransaction() {\n"
         << "      let amt = parseFloat(document.getElementById('amt').value);\n"
         << "      let recipient = document.getElementById('recipient').value.trim();\n"
         << "      let resultBox = document.getElementById('analystResult');\n"
         << "      \n"
         << "      if (isNaN(amt) || amt <= 0) {\n"
         << "        alert('Please enter a valid positive transaction amount.');\n"
         << "        return;\n"
         << "      }\n"
         << "      \n"
         << "      if (amt > 10000) {\n"
         << "        sarReportCount++;\n"
         << "        let repId = 'SAR-2026-' + (100 + sarReportCount);\n"
         << "        let dateStr = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';\n"
         << "        \n"
         << "        resultBox.className = 'result-box result-danger';\n"
         << "        resultBox.innerHTML = '<strong>🚨 SUSPICIOUS ACTIVITY REPORT TRIGGERED!</strong><br><br>' +\n"
         << "                              '<strong>Reason:</strong> Large Transaction ($' + amt.toLocaleString() + ' &gt; $10,000 threshold)<br>' +\n"
         << "                              '<strong>Recommended Action:</strong> Freeze Account &amp; Verify Identity.<br><br>' +\n"
         << "                              '<em>Automated SAR Report #' + repId + ' has been generated and filed in Tab 4.</em><br><br>' +\n"
         << "                              '<button class=\"btn btn-primary\" onclick=\"switchTab(\\'tabSAR\\')\">View Generated SAR Report &rarr;</button>';\n"
         << "        \n"
         << "        // Append to SAR Tab dynamically\n"
         << "        let sarContainer = document.getElementById('sarReportsContainer');\n"
         << "        let newCard = document.createElement('div');\n"
         << "        newCard.className = 'sar-card';\n"
         << "        newCard.innerHTML = '<div class=\"sar-header\">' +\n"
         << "                            '  <span class=\"sar-id\">📑 ' + repId + '</span>' +\n"
         << "                            '  <span class=\"badge badge-danger\">STATUS: REGULATORY AUDIT REQUIRED</span>' +\n"
         << "                            '</div>' +\n"
         << "                            '<div class=\"sar-grid\">' +\n"
         << "                            '  <div><strong>Subject / Suspect:</strong> Active Customer (ACC-789012)</div>' +\n"
         << "                            '  <div><strong>Flagged Amount:</strong> $' + amt.toLocaleString() + '.00</div>' +\n"
         << "                            '  <div><strong>Filing Timestamp:</strong> ' + dateStr + '</div>' +\n"
         << "                            '  <div><strong>Recipient:</strong> ' + recipient + '</div>' +\n"
         << "                            '</div>' +\n"
         << "                            '<div class=\"sar-reason\"><strong>Reason for SAR:</strong> Large Transaction: Single transfer of $' + amt.toLocaleString() + ' exceeds statutory threshold of $10,000.</div>' +\n"
         << "                            '<div class=\"sar-action\"><strong>Recommended Action:</strong> Freeze Account &amp; Verify Identity. Escalate to Compliance Team.</div>';\n"
         << "        sarContainer.prepend(newCard);\n"
         << "        \n"
         << "      } else {\n"
         << "        resultBox.className = 'result-box result-success';\n"
         << "        resultBox.innerHTML = '<strong>✅ Transaction Normal &amp; Cleared</strong><br>' +\n"
         << "                              'Amount $' + amt.toLocaleString() + ' is within standard $10,000 threshold.<br>' +\n"
         << "                              'No SAR filing required.';\n"
         << "      }\n"
         << "    }\n"
         << "  </script>\n"
         << "</body>\n"
         << "</html>\n";

    return page.str();
}

// ----------------------------------------------------------------------------
// 7. WINSOCK2 MULTI-CLIENT HTTP SERVER
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
        cerr << "[-] Socket creation failed. Error Code: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(9090);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        cerr << "[-] Bind failed on port 9090. Error Code: " << WSAGetLastError() << endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    if (listen(server_fd, 10) == SOCKET_ERROR) {
        cerr << "[-] Listen failed. Error Code: " << WSAGetLastError() << endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    SARSystemManager manager;

    cout << "===================================================================\n";
    cout << "  Design & Implementation of Automated SAR Generation System (OOPS)\n";
    cout << "===================================================================\n";
    cout << "[+] Server running at http://localhost:9090\n";
    cout << "[+] 4 Switchable Tabs Active:\n";
    cout << "    1. Customer Login (alice/1234, bob/5678)\n";
    cout << "    2. Transaction History (Previous: $3000, $4500, $12000)\n";
    cout << "    3. AML Analyst & Rules Engine (Amount > $10,000 threshold)\n";
    cout << "    4. Generated Structured SAR Reports (Freeze Account Action)\n";
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

            string response = generateFullPage(manager);
            send(client_fd, response.c_str(), (int)response.size(), 0);
        }

        closesocket(client_fd);
    }

    closesocket(server_fd);
    WSACleanup();
    return 0;
}
