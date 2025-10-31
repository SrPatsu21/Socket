/*
 * Usage: ./smtp_client <port> <server_url> <from_email> <app_password> <to_email> <subject> <body> [-v] [--buffsize <bytes>] [--attach <filepath>]
 * Example: ./smtp_client 587 smtp.gmail.com sender@gmail.com your_app_password recipient@gmail.com "Hello" "This is a test." --attach ./file.txt -v
 * Example: ./smtp_client 25 mail.example.com sender@example.com pass123 recipient@example.com "Hi" "Body text" -v --buffsize 1024
 *
 * NOTES:
 *  - For Gmail: use port 587 (STARTTLS) or 465 (implicit SSL)
 *  - Gmail requires an App Password if 2FA is enabled
 *  - Compile with: g++ main.cpp -o smtp_client -lssl -lcrypto
 */

#include <cstring> // strings
#include <vector>
#include <iostream> // output (cout, cin)
#include <netinet/in.h> // socket struct and utils (sockaddr_in)
#include <sys/socket.h> // create socket
#include <unistd.h> // posix close(), read(), write()
#include <arpa/inet.h> // inet_pton()
#include <netdb.h> // resolve hostname
#include <string> // more string utils
#include <cerrno> // print message immediately - unbuffered
#include <fstream>
#include <openssl/ssl.h> // TLS/SSL
#include <openssl/err.h> // TLS/SSL errors
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <map>

// Encode a string into Base64 using OpenSSL
std::string base64Encode(const std::string &input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64()); // Base64 filter
    bio = BIO_new(BIO_s_mem()); // Memory BIO to hold the output
    bio = BIO_push(b64, bio); // Filter with the memory BIO
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Disable newlines in the output
    BIO_write(bio, input.c_str(), input.size()); // Write the input data to the BIO chain
    BIO_flush(bio); // Ensure all pending data is written to the memory BIO
    BIO_get_mem_ptr(bio, &bufferPtr); // Retrieve the pointer to the encoded data
    std::string encoded(bufferPtr->data, bufferPtr->length); // Copy the encoded data into a std::string
    BIO_free_all(bio); // Free BIO objects
    return encoded;
}

// Encode a file into Base64 using OpenSSL
std::string readFileBase64(const std::string &path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Error: cannot open file " << path << std::endl;
        return "";
    }
    std::string data(
        (std::istreambuf_iterator<char>(file)), // begin iterator: reads bytes from the file stream
        std::istreambuf_iterator<char>() // end iterator: default-constructed = "end of stream"
    );
    return base64Encode(data);
}

// Very extension → MIME type mapping
std::string getMimeType(const std::string &filename) {
    static const std::map<std::string, std::string> mimeTypes = {
        {".txt", "text/plain"},
        {".html", "text/html"},
        {".htm", "text/html"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".png", "image/png"},
        {".gif", "image/gif"},
        {".pdf", "application/pdf"},
        {".csv", "text/csv"},
        {".json", "application/json"},
        {".xml", "application/xml"},
        {".mp3", "audio/mpeg"},
        {".mp4", "video/mp4"},
        {".zip", "application/zip"},
        {".rar", "application/vnd.rar"},
        {".7z", "application/x-7z-compressed"}
    };

    size_t dot = filename.find_last_of('.');
    if (dot != std::string::npos) {
        std::string ext = filename.substr(dot);
        auto it = mimeTypes.find(ext);
        if (it != mimeTypes.end()) {
            return it->second;
        }
    }

    // Default for unknown types
    return "application/octet-stream";
}


class SMTPSocketClient
{
private:
    int port;
    std::string address;
    std::string from;
    std::string to;
    std::string subject;
    std::string body;
    std::vector<std::string> attachments;
    bool verbose;
    int buffsize;

    // socket
    int clientSocket;
    char *buffer;
    sockaddr_in serverAddress;

    // TLS/SSL members
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    bool useTLS = false;

    // optional authentication
    std::string username;
    std::string password;

    std::string readResponse() {
        std::string resp;
        ssize_t n;

        if (this->useTLS) {
            n = SSL_read(this->ssl, this->buffer, this->buffsize - 1);
        } else {
            n = recv(this->clientSocket, this->buffer, this->buffsize - 1, 0);
        }

        if (n <= 0) return "ERROR or closed connection\n";
        this->buffer[n] = '\0';
        resp.assign(this->buffer, (size_t)n);
        return resp;
    }

    int sendAll(const std::string &data) {
        ssize_t total = 0;
        ssize_t len = (ssize_t)data.size();
        //loop to send all data
        while (total < len) {
            ssize_t sent = this->useTLS ?
                SSL_write(this->ssl, data.c_str() + total, len - total) :
                send(this->clientSocket, data.c_str() + total, len - total, 0);

            if (sent <= 0) {
                std::cerr << "Send error: " << std::strerror(errno) << "\n";
                return 1;
            }
            total += sent;
        }
        return 0;
    }

    int sendCommand(const std::string &cmd) {
        if (this->verbose) std::cout << "C: " << cmd;
        if (sendAll(cmd)) return 1;
        std::string reply = readResponse();
        std::cout << "S: " << reply;
        return 0;
    }

    void initTLS() {
        SSL_library_init(); // Init lib
        SSL_load_error_strings(); // Load human-readable error
        OpenSSL_add_all_algorithms(); // Load encryption algorithms and digests
        this->ctx = SSL_CTX_new(TLS_client_method()); // Context with client-side TLS method
        // if created successfully
        if (!this->ctx) {
            std::cerr << "Error initializing SSL context\n";
            exit(1); // Abort if initialization fails
        }
    }

    // TLS handshake
    int startTLS() {
        if (this->verbose) std::cout << "Starting TLS handshake...\n";
        initTLS(); // Initialize OpenSSL context and algorithms
        this->ssl = SSL_new(this->ctx); // Create (Secure Sockets Layer) object for this connection

        SSL_set_fd(this->ssl, this->clientSocket); // Attach the existing TCP socket to SSL

        // Perform the TLS handshake
        if (SSL_connect(this->ssl) <= 0) {
            ERR_print_errors_fp(stderr); // Print error, if fails
            return 1;
        }

        if (!SSL_set_tlsext_host_name(this->ssl, this->address.c_str()))
            std::cerr << "Warning: cannot set SNI\n";
        // Print the cipher being used for encryption
        if (this->verbose) std::cout << "[+] TLS connection established using " << SSL_get_cipher(ssl) << "\n";

        this->useTLS = true;
        return 0;
    }

public:
    SMTPSocketClient(
        int port,
        std::string &address,
        std::string &from,
        std::string &pass,
        std::string &to,
        std::string &subject,
        std::string &body,
        std::vector<std::string> &attachments,
        bool verbose = false,
        int buffsize = 1024
    ) :
        port(port),
        address(address),
        from(from),
        to(to),
        subject(subject),
        body(body),
        attachments(attachments),
        verbose(verbose),
        buffsize(buffsize),
        clientSocket(-1)
    {
        buffer = new char[buffsize];
        setCredentials(from, pass);
        displayInfo();
    }

    void setCredentials(const std::string &user, const std::string &pass) {
        this->username = user;
        this->password = pass;
    }

    void displayInfo() {
        if (this->verbose) {
            std::cout << "=== SMTP CLIENT CONFIG ===" << std::endl;
            std::cout << "Server URL: " << address << std::endl;
            std::cout << "Port: " << port << std::endl;
            std::cout << "From: " << from << std::endl;
            std::cout << "To: " << to << std::endl;
            if (attachments.empty())
                std::cout << "Attachments: (none)" << std::endl;
            else {
                std::cout << "Attachments:" << std::endl;
                for (const auto &a : attachments)
                    std::cout << "  - " << a << std::endl;
            }
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

        // For SSL direct ports like 465, start TLS immediately
        if (this->port == 465) {
            if (startTLS()) return 1;
        }

        // here because of gmail :/
        // Read server banner
        if (this->verbose) std::cout << "Server banner: " << readResponse() << std::endl;

        return 0;
    }

    int run() {
        if (createSocket()) return 1;

        std::cout << "Init communication" << std::endl;
        if (sendCommand(std::string("EHLO ") + this->address + "\r\n")) return 1;

        // STARTTLS if needed (for port 587)
        if (this->port == 587) {
            if (sendCommand("STARTTLS\r\n")) return 1;
            if (startTLS()) return 1;
            if (sendCommand(std::string("EHLO ") + this->address + "\r\n")) return 1;
        }

        // Authentication (required by Gmail)
        if (!this->username.empty() && !this->password.empty()) {
            if (sendCommand("AUTH LOGIN\r\n")) return 1;
            if (sendCommand(base64Encode(this->username) + "\r\n")) return 1;
            if (sendCommand(base64Encode(this->password) + "\r\n")) return 1;
        }

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

        // Create a unique boundary identifier used to separate Multipurpose Internet Mail Extensions(MIME) parts in the email
        std::string boundary = "----=_Boundary_" + std::to_string(rand());

        // If there's an attachment, build a multipart/mixed message
        if (!this->attachments.empty()) {
            // MIME headers to indicate that this email contains multiple parts (text + attachments)
            msg += "MIME-Version: 1.0\r\n";
            msg += "Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n";

            // Text part
            msg += "--" + boundary + "\r\n"; // Start of the first MIME section
            msg += "Content-Type: text/plain; charset=utf-8\r\n\r\n"; // Defines the content type as plain text
            msg += this->body + "\r\n\r\n"; // Adds the main message body

            // Attachment file
            for (const auto &path : attachments) {
                std::string fileData = readFileBase64(path);
                std::string filename = path.substr(path.find_last_of("/\\") + 1);
                std::string mimeType = getMimeType(filename);

                msg += "--" + boundary + "\r\n"; // Start of the second MIME section (attachment)
                msg += "Content-Type: " + mimeType + "; name=\"" + filename + "\"\r\n"; // Generic binary content type
                msg += "Content-Transfer-Encoding: base64\r\n"; // Tell the email client the data is Base64 encoded
                msg += "Content-Disposition: attachment; filename=\"" + filename + "\"\r\n\r\n"; // Marks this section as an attachment and sets its filename
                msg += fileData + "\r\n"; // Insert the Base64-encoded file content
            }
            msg += "--" + boundary + "--\r\n"; // End of the multipart message (final boundary)
        } else {
            // If no attachment, send a simple plain-text message
            msg += "Content-Type: text/plain; charset=utf-8\r\n\r\n";
            msg += this->body + "\r\n";
        }

        msg += ".\r\n";

        std::cout << std::endl << "Message data:" << std::endl << msg << std::endl;
        if (sendAll(msg)) return 1;

        // verify if starts with "220"
        std::string resp = readResponse();
        std::cout << "Server response: " << std::endl << resp << std::endl;

        // QUIT
        if (sendCommand("QUIT\r\n")) return 1;

        return 0;
    }

    ~SMTPSocketClient() {
        cleanup();
    }

    void cleanup() {
        if (this->ssl) {
            SSL_shutdown(this->ssl);
            SSL_free(this->ssl);
            SSL_CTX_free(this->ctx);
        }
        if (this->clientSocket >= 0) close(this->clientSocket);
        delete[] this->buffer;
        this->buffer = nullptr;
    }
};

int main(int argc, char *argv[])
{
    if (argc < 8) {
        std::cerr << "Usage: " << argv[0] << " <port> <server_url> <from_email> <app_password> <to_email> <subject> <body> [-v] [--buffsize <bytes>] [--attach <filepath>]" << std::endl;
        return 1;
    }

    //* Required args
    int port = std::stoi(argv[1]);
    std::string server = argv[2];
    std::string from = argv[3];
    std::string pass = argv[4];
    std::string to = argv[5];
    std::string subject = argv[6];
    std::string body = argv[7];

    //* Optional args
    bool verbose = false;
    int buffsize = 1024;
    std::vector<std::string> attachments;
    //* Resolve args
    for (int i = 8; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-v") verbose = true;
        else if (arg == "--buffsize" && i + 1 < argc)
            buffsize = std::stoi(argv[++i]);
        else if (arg == "--attach" && i + 1 < argc)
            attachments.push_back(argv[++i]);
    }

    SMTPSocketClient client(port, server, from, pass, to, subject, body, attachments, verbose, buffsize);

    return client.run();
}