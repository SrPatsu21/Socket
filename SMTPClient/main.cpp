/*
 * Setting args
 * Usage: ./smtp_client <port> [address] [-v] [--buffsize <bytes>]
 * Exemple: ./smtp_client 8080 127.0.0.1 -v --buffsize 1024
 */

#include <cstring> // strings
#include <iostream> // output (cout, cin)
#include <netinet/in.h> // socket struct and utils (sockaddr_in)
#include <sys/socket.h> // create socket
#include <unistd.h> // posix close(), read(), write()
#include <arpa/inet.h> // inet_pton()
#include <string> // more string utils
#include <cerrno> // print message immediately - unbuffered

class SMTPSocketClient
{
private:
    int port;
    std::string address;
    std::string from;
    std::string to;
    std::string subject;
    std::string body;
    bool verbose;
    int buffsize;

    // socket
    int clientSocket;
    char *buffer;
    sockaddr_in serverAddress;

    std::string readResponse() {
        std::string resp;
        ssize_t n = recv(this->clientSocket, this->buffer, this->buffsize - 1, 0);
        if (n <= 0) return "ERROR or closed connection\n";
        buffer[n] = '\0';
        resp.assign(buffer, (size_t)n);
        return resp;
    }

    int sendAll(const std::string &data) {
        ssize_t total = 0;
        ssize_t len = (ssize_t)data.size();
        //loop to send all data
        while (total < len) {
            ssize_t sent = send(this->clientSocket, data.c_str() + total, len - total, 0);
            if (sent <= 0) {
                std::cerr << "Send error: " << std::strerror(errno) << "\n";
                return 1;
            }
            total += sent;
        }
        return 0;
    }

    int sendCommand(const std::string &cmd) {
        if (verbose) std::cout << "C: " + cmd << std::endl;
        if (sendAll(cmd)) return 1;
        std::string reply = readResponse();
        std::cout << "S: " << reply;
        return 0;
    }

public:
    SMTPSocketClient(
        int port,
        std::string &address,
        std::string &from,
        std::string &to,
        std::string &subject,
        std::string &body,
        bool verbose = false,
        int buffsize = 1024
    ) :
        port(port),
        address(address),
        from(from),
        to(to),
        subject(subject),
        body(body),
        verbose(verbose),
        buffsize(buffsize),
        clientSocket(-1)
    {
        buffer = new char[buffsize];
        displayInfo();
    }

    void displayInfo() {
        if (this->verbose) {
            std::cout << "=== UDP SERVER CONFIG ===" << std::endl;
            std::cout << "Server Address: " << address << std::endl;
            std::cout << "Server Port: " << port << std::endl;
            std::cout << "Buffer size: " << buffsize << " bytes" << std::endl;
            std::cout << "Verbose mode enabled\n" << std::endl;
        }
    }

    int createSocket() {
        //* Create socket
        // AF_INET → IPv4
        // SOCK_DGRAM → UDP protocol (unlike SOCK_STREAM for TCP)
        // 0 → choose default protocol for UDP
        this->clientSocket = socket(AF_INET, SOCK_DGRAM, 0);

        // verify if socket was created
        if (this->clientSocket < 0) {
            std::cerr << "Error: failed to create socket.";
            return 1;
        }

        //* Define the server address we want to send to
        memset(&this->serverAddress, 0, sizeof(this->serverAddress)); // Clear structure memory


        this->serverAddress.sin_family = AF_INET; // IPv4
        this->serverAddress.sin_port = htons(port); // Host to Network Short (host byte order to network byte order)

        // Set network interface to listen
        if (inet_pton(AF_INET, this->address.c_str(), &this->serverAddress.sin_addr) <= 0) {
            std::cerr << "Invalid address: " << this->address << std::endl;
            close(this->clientSocket);
            return 1;
        }

        std::cout << "UDP client started. Type messages to send to the server." << std::endl;
        return 0;
    }

    int connectServer() {

        if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
            std::cerr << "Connect error: " << std::strerror(errno) << "\n";
            return 1;
        }

        std::cout << "Connected to " << address << ":" << port << "\n";
        std::cout << "Server: " << readResponse(); // banner
        return 0;
    }

    int run() {
        if (connectServer()) return 1;

        // EHLO
        if (!sendCommand("EHLO localhost\r\n")) return false;

        // MAIL FROM
        if (!sendCommand("MAIL FROM:<" + from + ">\r\n")) return false;

        // RCPT TO
        if (!sendCommand("RCPT TO:<" + to + ">\r\n")) return false;

        // DATA
        if (!sendCommand("DATA\r\n")) return false;

        // Message headers + body
        std::string msg = "Subject: " + subject + "\r\n";
        msg += "From: <" + from + ">\r\n";
        msg += "To: <" + to + ">\r\n";
        msg += "\r\n" + body + "\r\n";
        msg += ".\r\n";

        std::cout << "C (message data):\n" << msg;
        if (sendAll(msg)) return 1;

        std::cout << "S: " << readResponse();

        // QUIT
        if (!sendCommand("QUIT\r\n")) return false;

        return 0;
    }

    ~SMTPSocketClient(){
        cleanup();
    };

    void cleanup(){
        close(this->clientSocket);
        delete[] this->buffer;
        this->buffer = nullptr;
    }
};

int main(int argc, char *argv[])
{
    if (argc < 7)
    {
        std::cerr << "Usage: " << argv[0] << " <port> <server_ip> <from_email> <to_email> <subject> <body> [-v]" << std::endl;
        return 1;
    }

    //* Required args
    int port = std::stoi(argv[1]);
    std::string server = argv[2];
    std::string from = argv[3];
    std::string to = argv[4];
    std::string subject = argv[5];
    std::string body = argv[6];
    //* Optional args
    bool verbose = (argc > 7 && std::string(argv[7]) == "-v");

    SMTPSocketClient client(port, server, from, to, subject, body, verbose);

    if (client.createSocket() != 0) return 1;

    return client.run();
}
