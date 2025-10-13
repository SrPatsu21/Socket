/*
 * Usage: ./smtp_client <port> <server_url> <from_email> <to_email> <subject> <body> [-v] [--buffsize <bytes>]
 * Example: ./smtp_client 25 temp-mail.org sender@example.com hosidav674@gamegta.com "Hello" "This is a test." -v --buffsize 2048
 * Example: ./smtp_client 25 localhost sender@example.com recipient@example.com "Hello" "This is a test" -v --buffsize 2048
 */

#include <cstring> // strings
#include <iostream> // output (cout, cin)
#include <netinet/in.h> // socket struct and utils (sockaddr_in)
#include <sys/socket.h> // create socket
#include <unistd.h> // posix close(), read(), write()
#include <arpa/inet.h> // inet_pton()
#include <netdb.h> // resolve hostname
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
        if (verbose) std::cout << "C: " << cmd;
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
            std::cout << "=== SMTP CLIENT CONFIG ===" << std::endl;
            std::cout << "Server URL: " << address << std::endl;
            std::cout << "Port: " << port << std::endl;
            std::cout << "From: " << from << std::endl;
            std::cout << "To: " << to << std::endl;
            std::cout << "Buffer size: " << buffsize << " bytes" << std::endl;
            std::cout << "Verbose mode enabled" << std::endl;
            std::cout << "==========================" << std::endl << std::endl;
        }
    }

    int createSocket() {
        //* Create socket
        // AF_INET → IPv4
        // SOCK_DGRAM → UDP protocol (unlike SOCK_STREAM for TCP)
        // 0 → choose default protocol for UDP            std::cout << "=== SMTP CLIENT CONFIG ===" << std::endl;

        this->clientSocket = socket(AF_INET, SOCK_STREAM, 0);

        // Verify if socket was created
        if (this->clientSocket < 0) {
            std::cerr << "Error: failed to create socket: " << std::strerror(errno) << std::endl;
            return 1;
        }

        //* Define the server address we want to send to
        memset(&this->serverAddress, 0, sizeof(this->serverAddress)); // Clear structure memory

        this->serverAddress.sin_family = AF_INET; // IPv4
        this->serverAddress.sin_port = htons(port); // Host to Network Short (host byte order to network byte order)

        // Resolve hostname or IP
        struct hostent *host = gethostbyname(this->address.c_str());
        if (!host) {
            std::cerr << "Error: could not resolve hostname " << this->address << std::endl;
            return 1;
        }
        memcpy(&this->serverAddress.sin_addr, host->h_addr, host->h_length);

        if (connect(this->clientSocket, (struct sockaddr *)&this->serverAddress, sizeof(this->serverAddress)) < 0) {
            std::cerr << "Connect error: " << std::strerror(errno) << std::endl;
            return 1;
        }

        std::cout << "Connected to " << this->address << ":" << this->port << std::endl;

        // Read server banner
        if (this->verbose) std::cout << "Server banner: " << readResponse() << std::endl;
        return 0;
    }

    int run() {
        if (createSocket()) return 1;

        std::cout << "Init communication" << std::endl;
        // EHLO
        if (sendCommand(std::string("EHLO ") + this->address + "\r\n")) return 1;

        // MAIL FROM
        if (sendCommand("MAIL FROM:<" + this->from + ">\r\n")) return 1;

        // RCPT TO
        if (sendCommand("RCPT TO:<" + this->to + ">\r\n")) return 1;

        // DATA
        if (sendCommand("DATA\r\n")) return 1;

        // Message headers + body
        std::string msg = "Subject: " + this->subject + "\r\n";
        msg += "From: <" + this->from + ">\r\n";
        msg += "To: <" + this->to + ">\r\n";
        msg += "Content-Type: text/plain; charset=utf-8\r\n";
        msg += "\r\n" + this->body + "\r\n";
        msg += ".\r\n";

        std::cout << std::endl << "Message data:" << std::endl << msg << std::endl;
        if (sendAll(msg)) return 1;
        std::cout << "Server response: " << std::endl << readResponse() << std::endl;

        // QUIT
        if (sendCommand("QUIT\r\n")) return 1;

        return 0;
    }

    ~SMTPSocketClient() {
        cleanup();
    }

    void cleanup() {
        if (this->clientSocket >= 0) close(this->clientSocket);
        delete[] this->buffer;
        this->buffer = nullptr;
    }
};

int main(int argc, char *argv[])
{
    if (argc < 7) {
        std::cerr << "Usage: " << argv[0] << " <port> <server_url> <from_email> <to_email> <subject> <body> [-v] [--buffsize <bytes>]" << std::endl;
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
    bool verbose = false;
    int buffsize = 1024;

    //* Resolve args
    for (int i = 7; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v") verbose = true;
        else if (arg == "--buffsize" && i + 1 < argc)
            buffsize = std::stoi(argv[++i]);
    }

    SMTPSocketClient client(port, server, from, to, subject, body, verbose, buffsize);
    return client.run();
}