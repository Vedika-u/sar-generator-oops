#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include <iomanip>
#include <thread>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

// ============================================================
// 1. ABSTRACT BASE CLASS: BaseTransaction (Demonstrates Abstraction & Polymorphism)
// ============================================================
class BaseTransaction {
protected:
    string id;
    string type;
    double amount;
    int hour; // 0-23
    string sender;
    string recipient;

public:
    BaseTransaction(string id, string type, double amount, int hour, string sender, string recipient)
        : id(id), type(type), amount(amount), hour(hour), sender(sender), recipient(recipient) {}

    virtual ~BaseTransaction() = default;

    virtual double calculateRiskScore() const = 0;
    virtual string getRiskCategory() const = 0;

    string getId() const { return id; }
    string getType() const { return type; }
    double getAmount() const { return amount; }
    int getHour() const { return hour; }
    string getSender() const { return sender; }
    string getRecipient() const { return recipient; }

    virtual string toHTMLRow() const {
        double risk = calculateRiskScore();
        string badgeClass = (risk >= 70) ? "badge-danger" : ((risk >= 40) ? "badge-warning" : "badge-success");
        stringstream ss;
        ss << fixed << setprecision(2) << amount;
        return "<tr>"
               "<td>" + id + "</td>"
               "<td>" + type + "</td>"
               "<td>$" + ss.str() + "</td>"
               "<td>" + to_string(hour) + ":00</td>"
               "<td>" + sender + " &rarr; " + recipient + "</td>"
               "<td><span class='badge " + badgeClass + "'>" + to_string((int)risk) + "% (" + getRiskCategory() + ")</span></td>"
               "</tr>";
    }
};

// ============================================================
// 2. DERIVED CLASS: DomesticTransaction (Demonstrates Inheritance)
// ============================================================
class DomesticTransaction : public BaseTransaction {
public:
    DomesticTransaction(string id, string type, double amount, int hour, string sender, string recipient)
        : BaseTransaction(id, type, amount, hour, sender, recipient) {}

    double calculateRiskScore() const override {
        double score = 10.0;
        if (amount > 10000.0) score += 40.0;
        if (amount > 25000.0) score += 30.0;
        if (hour >= 23 || hour <= 4) score += 20.0; // Unusual nocturnal transfer
        return (score > 100.0) ? 100.0 : score;
    }

    string getRiskCategory() const override {
        double score = calculateRiskScore();
        if (score >= 70.0) return "High Risk";
        if (score >= 40.0) return "Medium Risk";
        return "Low Risk";
    }
};

// ============================================================
// 3. DERIVED CLASS: InternationalWireTransaction (Polymorphic Risk Engine)
// ============================================================
class InternationalWireTransaction : public BaseTransaction {
private:
    string countryCode;

public:
    InternationalWireTransaction(string id, double amount, int hour, string sender, string recipient, string country)
        : BaseTransaction(id, "International Wire", amount, hour, sender, recipient), countryCode(country) {}

    double calculateRiskScore() const override {
        double score = 25.0; // Base international wire baseline
        if (amount > 10000.0) score += 45.0;
        if (amount > 50000.0) score += 30.0;
        if (hour >= 23 || hour <= 4) score += 15.0;
        return (score > 100.0) ? 100.0 : score;
    }

    string getRiskCategory() const override {
        double score = calculateRiskScore();
        if (score >= 70.0) return "Suspicious (SAR Required)";
        if (score >= 40.0) return "Enhanced Due Diligence";
        return "Standard International";
    }

    string toHTMLRow() const override {
        double risk = calculateRiskScore();
        string badgeClass = (risk >= 70) ? "badge-danger" : ((risk >= 40) ? "badge-warning" : "badge-success");
        stringstream ss;
        ss << fixed << setprecision(2) << amount;
        return "<tr>"
               "<td>" + id + "</td>"
               "<td>" + type + " (" + countryCode + ")</td>"
               "<td>$" + ss.str() + "</td>"
               "<td>" + to_string(hour) + ":00</td>"
               "<td>" + sender + " &rarr; " + recipient + "</td>"
               "<td><span class='badge " + badgeClass + "'>" + to_string((int)risk) + "% (" + getRiskCategory() + ")</span></td>"
               "</tr>";
    }
};

// ============================================================
// 4. TRANSACTION MANAGER (Demonstrates Encapsulation & Smart Pointers)
// ============================================================
class TransactionManager {
private:
    vector<shared_ptr<BaseTransaction>> transactions;
    mutable mutex mtx;

public:
    TransactionManager() {
        // Pre-populate with realistic banking telemetry
        addTransaction(make_shared<DomesticTransaction>("TXN-1001", "Checking Transfer", 3200.0, 14, "Account #4401", "Account #9122"));
        addTransaction(make_shared<DomesticTransaction>("TXN-1002", "ATM Cash Withdrawal", 15400.0, 2, "Account #3190", "External ATM"));
        addTransaction(make_shared<InternationalWireTransaction>("TXN-1003", 28500.0, 16, "Corporate Acct #0012", "Offshore Partner Ltd", "CH"));
        addTransaction(make_shared<DomesticTransaction>("TXN-1004", "Peer-to-Peer Transfer", 450.0, 11, "Account #8872", "Account #1104"));
        addTransaction(make_shared<InternationalWireTransaction>("TXN-1005", 85000.0, 3, "Account #7721", "Global Holdings Inc", "CY"));
    }

    void addTransaction(shared_ptr<BaseTransaction> txn) {
        lock_guard<mutex> lock(mtx);
        transactions.push_back(txn);
    }

    string getAllRowsHTML() const {
        lock_guard<mutex> lock(mtx);
        string rows = "";
        for (const auto& txn : transactions) {
            rows += txn->toHTMLRow();
        }
        return rows;
    }

    int getTotalSARCount() const {
        lock_guard<mutex> lock(mtx);
        int count = 0;
        for (const auto& txn : transactions) {
            if (txn->calculateRiskScore() >= 70.0) count++;
        }
        return count;
    }

    size_t size() const {
        lock_guard<mutex> lock(mtx);
        return transactions.size();
    }
};

// ============================================================
// 5. HTML PAGE BUILDER (UI Generation Engine)
// ============================================================
class PageBuilder {
public:
    static string buildDashboard(const TransactionManager& mgr) {
        string rows = mgr.getAllRowsHTML();
        string sarCount = to_string(mgr.getTotalSARCount());
        string totalTxns = to_string(mgr.size());

        return "<!DOCTYPE html>"
               "<html lang='en'>"
               "<head>"
               "<meta charset='UTF-8'>"
               "<title>Automated SAR Generation System</title>"
               "<style>"
               "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }"
               ".container { max-width: 1050px; margin: 0 auto; }"
               ".header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }"
               "h1 { margin: 0; font-size: 24px; color: #38bdf8; font-weight: 700; }"
               ".subtitle { color: #94a3b8; font-size: 14px; margin-top: 4px; }"
               ".stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }"
               ".stat-card { background: #1e293b; border: 1px solid #334155; padding: 18px; border-radius: 8px; }"
               ".stat-val { font-size: 28px; font-weight: bold; color: #f8fafc; margin-top: 4px; }"
               ".stat-danger { color: #f43f5e; }"
               ".card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 24px; }"
               "h2 { font-size: 18px; margin-top: 0; color: #e2e8f0; border-bottom: 1px solid #334155; padding-bottom: 10px; }"
               "table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; margin-top: 12px; }"
               "th, td { padding: 12px 14px; border-bottom: 1px solid #334155; }"
               "th { background: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 12px; }"
               ".badge { padding: 4px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; display: inline-block; }"
               ".badge-success { background: #064e3b; color: #34d399; }"
               ".badge-warning { background: #78350f; color: #fbbf24; }"
               ".badge-danger { background: #881337; color: #fda4af; }"
               ".form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 16px; }"
               "input, select, button { padding: 10px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; font-size: 14px; }"
               "button { background: #0284c7; border: none; cursor: pointer; font-weight: 600; transition: background 0.2s; }"
               "button:hover { background: #0369a1; }"
               ".footer { text-align: center; color: #64748b; font-size: 13px; margin-top: 32px; border-top: 1px solid #1e293b; padding-top: 16px; }"
               "</style>"
               "</head>"
               "<body>"
               "<div class='container'>"
               "  <div class='header'>"
               "    <div>"
               "      <h1>Automated Suspicious Activity Report (SAR) System</h1>"
               "      <div class='subtitle'>C++ Multi-threaded Winsock2 HTTP Server &amp; Risk Classification Engine</div>"
               "    </div>"
               "    <div><span class='badge badge-success'>System Online: Port 9090</span></div>"
               "  </div>"
               "  <div class='stats-grid'>"
               "    <div class='stat-card'><div>Total Telemetry Events</div><div class='stat-val'>" + totalTxns + "</div></div>"
               "    <div class='stat-card'><div>Critical SAR Alerts Flagged</div><div class='stat-val stat-danger'>" + sarCount + "</div></div>"
               "    <div class='stat-card'><div>Engine Backend</div><div class='stat-val' style='font-size:20px; color:#38bdf8;'>Modern C++ / Winsock</div></div>"
               "  </div>"
               "  <div class='card'>"
               "    <h2>Live Ingested Banking Transactions</h2>"
               "    <table>"
               "      <thead><tr><th>TXN ID</th><th>Type</th><th>Amount</th><th>Timestamp</th><th>Route</th><th>SAR Risk Evaluation</th></tr></thead>"
               "      <tbody>" + rows + "</tbody>"
               "    </table>"
               "  </div>"
               "  <div class='footer'>Automated SAR Generation System &bull; Designed &amp; Developed with C++ Object-Oriented Architecture</div>"
               "</div>"
               "</body></html>";
    }
};

// ============================================================
// 6. MULTI-THREADED WINSOCK2 HTTP SERVER (Demonstrates Sockets & Concurrency)
// ============================================================
class HTTPServer {
private:
    int port;
    SOCKET listenSocket;
    bool running;
    TransactionManager& txnManager;

    void handleClient(SOCKET clientSocket) {
        char buffer[2048] = {0};
        int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        if (bytesRead > 0) {
            string request(buffer, bytesRead);
            string html = PageBuilder::buildDashboard(txnManager);

            stringstream response;
            response << "HTTP/1.1 200 OK\r\n"
                     << "Content-Type: text/html; charset=UTF-8\r\n"
                     << "Content-Length: " << html.length() << "\r\n"
                     << "Connection: close\r\n\r\n"
                     << html;

            string respStr = response.str();
            send(clientSocket, respStr.c_str(), (int)respStr.length(), 0);
        }

        closesocket(clientSocket);
    }

public:
    HTTPServer(int p, TransactionManager& tm) : port(p), listenSocket(INVALID_SOCKET), running(false), txnManager(tm) {}

    bool start() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            cerr << "[ERROR] WSAStartup failed.\n";
            return false;
        }

        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            cerr << "[ERROR] Failed to create socket: " << WSAGetLastError() << "\n";
            WSACleanup();
            return false;
        }

        // Allow immediate port reuse
        int opt = 1;
        setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);

        if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            cerr << "[ERROR] Bind failed on port " << port << " with error: " << WSAGetLastError() << "\n";
            closesocket(listenSocket);
            WSACleanup();
            return false;
        }

        if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
            cerr << "[ERROR] Listen failed: " << WSAGetLastError() << "\n";
            closesocket(listenSocket);
            WSACleanup();
            return false;
        }

        running = true;
        cout << "========================================================\n";
        cout << " [SUCCESS] SAR Generation HTTP Server is RUNNING!\n";
        cout << " Open your browser: http://localhost:" << port << "\n";
        cout << " Press Ctrl+C in this terminal to stop the server.\n";
        cout << "========================================================\n";

        while (running) {
            sockaddr_in clientAddr{};
            int clientAddrLen = sizeof(clientAddr);
            SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrLen);

            if (clientSocket != INVALID_SOCKET) {
                // Multi-threaded connection handling
                thread(&HTTPServer::handleClient, this, clientSocket).detach();
            }
        }

        return true;
    }

    void stop() {
        running = false;
        if (listenSocket != INVALID_SOCKET) {
            closesocket(listenSocket);
            listenSocket = INVALID_SOCKET;
        }
        WSACleanup();
    }

    ~HTTPServer() {
        stop();
    }
};

// ============================================================
// MAIN ENTRY POINT
// ============================================================
int main() {
    TransactionManager manager;
    HTTPServer server(9090, manager);
    server.start();
    return 0;
}
