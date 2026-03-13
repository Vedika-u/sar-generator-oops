#include <iostream>
#include <winsock2.h>
#include <string>
#include <vector>

#pragma comment(lib,"ws2_32.lib")

using namespace std;

// ============================================================
// CLASS 1: Transaction
// Represents a single bank transaction with its amount & type
// ============================================================
class Transaction {
private:
    string type;   // Type of transaction e.g. "Withdrawal"
    int amount;    // Amount in currency units

public:
    // Constructor: Initialize transaction with type and amount
    Transaction(string t, int a) : type(t), amount(a) {}

    // Getter for amount
    int getAmount() const { return amount; }

    // Getter for type
    string getType() const { return type; }

    // Returns an HTML <tr> row for this transaction
    string toHTMLRow() const {
        return "<tr><td>" + type + "</td><td>" + to_string(amount) + "</td></tr>";
    }
};

// ============================================================
// CLASS 2: TransactionManager
// Manages a collection of Transaction objects
// ============================================================
class TransactionManager {
private:
    vector<Transaction> transactions; // Stores all transactions

public:
    // Constructor: Load default/sample transactions
    TransactionManager() {
        // Adding sample transaction data
        transactions.push_back(Transaction("Withdrawal", 3000));
        transactions.push_back(Transaction("Withdrawal", 4500));
        transactions.push_back(Transaction("Withdrawal", 12000));
        transactions.push_back(Transaction("Withdrawal", 8000));
        transactions.push_back(Transaction("Withdrawal", 15000));
    }

    // Add a new transaction to the list
    void addTransaction(Transaction t) {
        transactions.push_back(t);
    }

    // Build and return all transactions as HTML table rows
    string getAllRowsHTML() const {
        string rows = "";
        for (const Transaction& t : transactions) {
            rows += t.toHTMLRow(); // Each transaction converts itself to HTML
        }
        return rows;
    }
};

// ============================================================
// CLASS 3: SARAnalyzer
// Analyzes transaction risk and generates SAR report logic (JS)
// This class holds the JS analysis logic as a string
// ============================================================
class SARAnalyzer {
public:
    // Returns the JavaScript analyze() function as a string
    // This is embedded into the HTML page served to the browser
    static string getAnalyzeScript() {
        return
            // analyze() is called when user clicks 'Analyze Transaction'
            "function analyze(){"

            // Read user inputs from the form
            "let amt=parseInt(document.getElementById('amt').value);"
            "let time=parseInt(document.getElementById('time').value);"

            // Initialize risk score and reason string
            "let risk=0;"
            "let reason='';"

            // Input validation: check for empty or non-numeric values
            "if(isNaN(amt)||isNaN(time)){"
            "document.getElementById('sarOutput').innerHTML='<span style=\"color:red\">Please enter valid number inputs.</span>';"
            "return;"
            "}"

            // Input validation: time must be between 0 and 23
            "if(time<0||time>23){"
            "document.getElementById('sarOutput').innerHTML='<span style=\"color:red\">Time must be between 0 and 23.</span>';"
            "return;"
            "}"

            // Input validation: amount must be positive
            "if(amt<=0){"
            "document.getElementById('sarOutput').innerHTML='<span style=\"color:red\">Amount must be greater than 0.</span>';"
            "return;"
            "}"

            // Rule 3 checked FIRST (more specific) — amt > 20000 is a superset of > 10000
            // Using else-if avoids double-counting risk for same amount condition
            "if(amt>20000){"
            "risk+=80;"  // High risk: covers both large + very high in one score
            "reason+='Very high withdrawal (critical threshold exceeded)<br>';"
            "}"
            // Rule 1: Large transaction (but NOT already caught by Rule 3)
            "else if(amt>10000){"
            "risk+=50;"
            "reason+='Large transaction compared to normal behavior<br>';"
            "}"

            // Rule 2: Unusual late night activity check (10PM - 5AM)
            // Independent of amount, so always checked separately
            "if(time>=22||time<=5){"
            "risk+=20;"
            "reason+='Unusual late-night activity<br>';"
            "}"

            // If no rules triggered, mark as normal
            "if(reason===''){"
            "reason='No suspicious pattern detected.';"
            "}"

            // Build the SAR report string
            "let report=\"<b>SAR REPORT</b><br><br>\""
            "+\"Risk Score: \"+risk+\"/100<br><br>\""
            "+\"Reasons:<br>\"+reason;"

            // Display report on screen
            "document.getElementById('sarOutput').innerHTML=report;"

            // Save report to the reports array for later viewing
            "sarReports.push(report);"
            "}";
    }
};

// ============================================================
// CLASS 4: PageBuilder
// Builds the complete HTML page with CSS, JS, and dynamic data
// ============================================================
class PageBuilder {
private:
    string transactionRows; // HTML rows for transaction table

public:
    // Constructor: Takes pre-built HTML rows from TransactionManager
    PageBuilder(string rows) : transactionRows(rows) {}

    // Returns CSS styles as a string
    string getStyles() const {
        return
            "<style>"
            "body{margin:0;font-family:Arial;background:#0f172a;color:white;}"
            "header{background:#020617;padding:20px;text-align:center;font-size:24px;color:#22c55e;}"
            "#login{width:350px;margin:100px auto;background:#1e293b;padding:30px;border-radius:10px;text-align:center;}"
            "input{width:90%;padding:10px;margin:10px;border-radius:5px;border:none;}"
            "button{padding:10px 20px;background:#22c55e;border:none;color:white;border-radius:5px;cursor:pointer;}"
            "#dashboard{display:none;padding:30px;}"
            ".menu{margin-bottom:20px;}"
            ".menu button{margin-right:10px;}"
            ".card{background:#1e293b;padding:20px;border-radius:10px;margin-top:20px;}"
            "table{width:100%;border-collapse:collapse;}"
            "td{padding:10px;border-bottom:1px solid #334155;}"
            "#sarOutput{color:#facc15;font-size:18px;margin-top:15px;}"
            "</style>";
    }

    // Returns the JavaScript logic as a string
    string getScript() const {
        return
            "<script>"

            // Global array to store all generated SAR reports
            "let sarReports=[];"

            // login() validates credentials (hardcoded for demo)
            "function login(){"
            "let u=document.getElementById('user').value;"
            "let p=document.getElementById('pass').value;"
            // Check for valid users: alice or bob
            "if((u=='kanchan' && p=='1234')||(u=='vedika' && p=='5678')){"
            "document.getElementById('login').style.display='none';"
            "document.getElementById('dashboard').style.display='block';"
            "showSAR();" // After login, show SAR form by default
            "}"
            "else{"
            "document.getElementById('msg').innerHTML='Invalid Login';"
            "}"
            "}"

            // showSAR() renders the SAR input form in the content area
            "function showSAR(){"
            "document.getElementById('content').innerHTML="
            "'<div class=\"card\">"
            "<h2>Generate Suspicious Activity Report</h2>"
            "Transaction Amount:<br>"
            "<input id=\"amt\"><br>"
            "Transaction Time (0-23):<br>"
            "<input id=\"time\"><br>"
            "<button onclick=\"analyze()\">Analyze Transaction</button>"
            "<div id=\"sarOutput\"></div>"
            "</div>'"
            "}"

            // Inject the analyze() function from SARAnalyzer class
            + SARAnalyzer::getAnalyzeScript() +

            // showReports() renders all stored SAR reports
            "function showReports(){"
            "let html='<div class=\"card\"><h2>SAR Reports</h2>';"
            "for(let r of sarReports){"
            "html+='<div style=\"margin-bottom:20px\">'+r+'</div>';"
            "}"
            "html+='</div>';"
            "document.getElementById('content').innerHTML=html;"
            "}"

            // showTransactions() renders the transaction history table
            // Using double-quote delimited JS string to avoid conflict with HTML single quotes
            "function showTransactions(){"
            "document.getElementById('content').innerHTML="
            "\"<div class='card'>"
            "<h2>Transaction History</h2>"
            "<table>" + transactionRows + "</table>"  // Dynamic rows injected from C++ server-side
            "</div>\""
            "}"

            "</script>";
    }

    // Builds and returns the FULL HTML page as a string
    string buildPage() const {
        string html =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n\r\n"

            "<!DOCTYPE html>"
            "<html>"
            "<head>"
            "<title>AML SAR Monitoring System</title>"
            + getStyles() +   // Inject CSS
            "</head>"

            "<body>"

            // Page header
            "<header>Automated Suspicious Activity Report System</header>"

            // Login section (shown first)
            "<div id='login'>"
            "<h2>User Login</h2>"
            "<input id='user' placeholder='Username'><br>"
            "<input id='pass' type='password' placeholder='Password'><br>"
            "<button onclick='login()'>Login</button>"
            "<div id='msg'></div>"
            "</div>"

            // Dashboard section (hidden until login)
            "<div id='dashboard'>"
            "<div class='menu'>"
            "<button onclick='showSAR()'>Generate SAR</button>"
            "<button onclick='showReports()'>SAR Reports</button>"
            "<button onclick='showTransactions()'>Transaction History</button>"
            "</div>"
            "<div id='content'></div>"
            "</div>"

            + getScript() +   // Inject JS

            "</body>"
            "</html>";

        return html;
    }
};

// ============================================================
// CLASS 5: HTTPServer
// Handles all socket-level networking: bind, listen, accept, send
// ============================================================
class HTTPServer {
private:
    int port;                    // Port number to listen on
    SOCKET server_fd;            // Server socket file descriptor
    sockaddr_in server_addr;     // Server address structure
    TransactionManager txManager; // Manages transaction data

    // Initialize Winsock (Windows socket library)
    void initWinsock() {
        WSADATA wsa;
        // WSAStartup must be called before using any Winsock functions
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            cerr << "WSAStartup failed!\n";
            exit(1);
        }
    }

    // Create the TCP server socket
    void createSocket() {
        // AF_INET = IPv4, SOCK_STREAM = TCP
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == INVALID_SOCKET) {
            cerr << "Socket creation failed!\n";
            exit(1);
        }
    }

    // Bind the socket to a port and IP address
    void bindSocket() {
        server_addr.sin_family = AF_INET;           // IPv4
        server_addr.sin_port = htons(port);          // Convert to network byte order
        server_addr.sin_addr.s_addr = INADDR_ANY;    // Accept on all network interfaces

        if (bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
            cerr << "Bind failed!\n";
            exit(1);
        }
    }

    // Handle a single client connection: receive request, send response
    void handleClient(SOCKET client_fd) {
        // Buffer to store the incoming HTTP request
        char request[3000] = {0};  // Zero-initialize to avoid garbage data
        int bytesReceived = recv(client_fd, request, 3000, 0);

        // If recv failed or client disconnected early, close and return
        if (bytesReceived <= 0) {
            closesocket(client_fd);
            return;
        }

        // Get transaction HTML rows from manager
        string rows = txManager.getAllRowsHTML();

        // Use PageBuilder to build the full HTML page
        PageBuilder builder(rows);
        string page = builder.buildPage();

        // Send the page — send() may not send all bytes in one call on large responses
        // Loop until all bytes are sent
        int totalSent = 0;
        int pageLen = (int)page.size();
        while (totalSent < pageLen) {
            int sent = send(client_fd, page.c_str() + totalSent, pageLen - totalSent, 0);
            if (sent == SOCKET_ERROR) break; // Stop on error
            totalSent += sent;
        }

        // Close the client connection after sending
        closesocket(client_fd);
    }

public:
    // Constructor: Set the port for the server
    HTTPServer(int p) : port(p) {}

    // Start the server: setup, then enter accept loop
    void start() {
        initWinsock();
        createSocket();
        bindSocket();

        // Listen for incoming connections (max queue = 5)
        listen(server_fd, 5);

        cout << "Server running at http://localhost:" << port << "\n";

        // ---- Infinite request-handling loop ----
        while (true) {
            sockaddr_in client_addr;
            int client_len = sizeof(client_addr);

            // Block and wait for a new client to connect
            SOCKET client_fd = accept(server_fd, (sockaddr*)&client_addr, &client_len);

            if (client_fd == INVALID_SOCKET) {
                cerr << "Accept failed!\n";
                continue; // Skip bad connection and try again
            }

            // Handle the client request
            handleClient(client_fd);
        }

        // NOTE: WSACleanup() would be called here in a graceful shutdown scenario.
        // With an infinite loop above, this line is never reached in normal operation.
        // For production, handle SIGINT / OS signals to break the loop and call cleanup.
        // WSACleanup();
    }
};

// ============================================================
// MAIN FUNCTION
// Entry point: Creates and starts the HTTP server on port 9090
// ============================================================
int main() {
    // Create server object with port 9090
    HTTPServer server(9090);

    // Start server - this runs forever (infinite loop inside)
    server.start();

    return 0;
}
