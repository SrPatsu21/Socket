/*
 * Setting args
 * Usage: ./udp_server <port> [address] [-v] [--buffsize <bytes>] [--neterr <percent>] [--heartbeat <0|1>] [--heartms <ms>]
 * Exemple: ./udp_server 8080 -v --buffsize 1024 --neterr 25 --heartbeat 1 --heartms 3000
 */

#include <cstring> // strings
#include <iostream> // output (cout, cin)
#include <netinet/in.h> // socket struct and utils (sockaddr_in)
#include <sys/socket.h> // create socket
#include <unistd.h> // posix close(), read(), write()
#include <arpa/inet.h> // inet_pton()
#include <thread> // std::thread for heartbeat
#include <chrono> // std::chrono for timing
#include <cstdlib> // rand(), srand()
#include <ctime> // time()

class UDPSocketServer
{
private:
    int port;
    std::string address;
    bool verbose;
    int buffsize;
    int netErrorPercent;
    bool heartbeatEnabled;
    int heartbeatMs;
    // track last heartbeat number
    int lastN;
    int lostPackets;
    long long lastHeartbeatTime;
    // socket
    int serverSocket;
    char *buffer;
    sockaddr_in serverAddress;
public:
    UDPSocketServer(
        int port,
        std::string address = "0.0.0.0",
        bool verbose = false,
        int buffsize = 1024,
        int netErrorPercent = 0,
        bool heartbeatEnabled = false,
        int heartbeatMs = 3000
    ) :
        port(port),
        address(address),
        verbose(verbose),
        buffsize(buffsize),
        netErrorPercent(netErrorPercent),
        heartbeatEnabled(heartbeatEnabled),
        heartbeatMs(heartbeatMs)
    {
        // track last heartbeat number
        this->lastN = -1;
        this->lostPackets = 0;
        this->lastHeartbeatTime = 0; //never
        displayInfo();
    };

    void displayInfo(){
        if (verbose) {
            std::cout << "=== UDP SERVER CONFIG ===" << std::endl;
            std::cout << "Address: " << address << std::endl;
            std::cout << "Port: " << port << std::endl;
            std::cout << "Buffer size: " << buffsize << " bytes" << std::endl;
            std::cout << "Network error simulation: " << netErrorPercent << "%" << std::endl;
            std::cout << "Heartbeat: " << (heartbeatEnabled ? "ON" : "OFF") << " (" << heartbeatMs << " ms)" << std::endl;
            std::cout << "Verbose mode enabled\n" << std::endl;
        }
    }

    int createSocket(){
        //* Create socket
        // AF_INET → IPv4 address family
        // SOCK_DGRAM → UDP protocol (unlike SOCK_STREAM for TCP)
        // 0 → choose default protocol for UDP
        this->serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
        // verify if socket was created
        if (this->serverSocket < 0) {
            std::cerr << "Error: failed to create socket.";
            return 1;
        }

        //* Configure the server address
        memset(&this->serverAddress, 0, sizeof(this->serverAddress)); // Clear structure memory

        this->serverAddress.sin_family = AF_INET; // IPv4
        this->serverAddress.sin_port = htons(port); // Host to Network Short (host byte order to network byte order)

        // Set network interface to listen
        if (inet_pton(AF_INET, this->address.c_str(), &this->serverAddress.sin_addr) <= 0) {
            std::cerr << "Invalid address: " << this->address << std::endl;
            close(this->serverSocket);
            return 1;
        }

        //* Bind the socket
        if (bind(this->serverSocket, (struct sockaddr*)&this->serverAddress, sizeof(this->serverAddress)) < 0) {
            std::cerr << "Error: binding failed." << std::endl;
            close(this->serverSocket);
            return 1;
        }

        std::cout << "UDP server listening on " << this->address << ":" << this->port << std::endl;
        return 0;
    }

    int run(){
        //* Prepare to receive messages
        this->buffer = new char[this->buffsize]; // dynamic buffer
        // To save client address
        sockaddr_in clientAddress;
        socklen_t clientAddressLen = sizeof(clientAddress);

        // init heartbeat monitor
        if (heartbeatEnabled) {
            startHeartbeatMonitor();
        }

        //* Random for network error
        srand(static_cast<unsigned>(time(nullptr)));

        //* Main receive loop
        while (true) {
            memset(buffer, 0, buffsize); // Clear buffer before receiving new data

            // recvfrom() waits for a UDP packet and fills buffer + client info
            ssize_t bytesReceived = recvfrom(
                serverSocket,
                buffer,
                buffsize - 1, // Leave space for null terminator '\0'
                0, // Optional flags (MSG_DONTWAIT for non-blocking)
                (struct sockaddr*)&clientAddress, // Pointer to a structure that will be filled with the sender's (client's) IP address and port
                &clientAddressLen //size of the client's address structure
            );

            if (bytesReceived < 0) {
                std::cerr << "Error receiving data." << std::endl;
            }else
            {
                buffer[bytesReceived] = '\0';

                // Simulate network error (packet loss)
                int randomValue = rand() % 100;

                if (randomValue < netErrorPercent) {
                    if (verbose) std::cout << "Simulated packet loss for message: " << buffer << std::endl;
                }else
                {
                    std::string message(buffer);
                    if (verbose) std::cout << "Message from client: " << message << std::endl;

                    // send a response back to client
                    const char* response = "Unknown command"; // default response

                    if (message == "Ping") {
                        response = handlePing();
                    }
                    else if (message.rfind("Heartbeat,", 0) == 0) { // rfind with pos=0 → starts with "Heartbeat,"
                        response = handleHeartbeat(message);
                    }

                    sendto(
                        serverSocket,
                        response, // Response data
                        strlen(response), // Number of bytes to send
                        0, // Flags
                        (struct sockaddr*)&clientAddress, // client address
                        clientAddressLen //length of the address
                    );
                }
            }
        }
    }

    const char* handlePing(){
        return "Received by server";
    }
    void startHeartbeatMonitor() {
        if (!heartbeatEnabled) return;

        std::thread([this]() {
            while (true) {
                std::this_thread::sleep_for(std::chrono::milliseconds(this->heartbeatMs));

                long long now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

                if (this->lastHeartbeatTime > 0 && (now - this->lastHeartbeatTime) > this->heartbeatMs) {
                    std::cout << "No heartbeat received in " << this->heartbeatMs << " ms. Client may be disconnected." << std::endl;
                    this->lastHeartbeatTime = now;
                }
            }
        }).detach();
    }
    const char* handleHeartbeat(std::string message){
        size_t firstComma = message.find(',');
        size_t secondComma = message.find(',', firstComma + 1);

        if (firstComma != std::string::npos && secondComma != std::string::npos) {
            int N = std::stoi(message.substr(firstComma + 1, secondComma - firstComma - 1));
            long long clientTime = std::stoll(message.substr(secondComma + 1));

            // get current server time (ms)
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();

            // latency = server_time_now - client_send_time
            long long latency = now - clientTime;

            // detect lost packets (if sequence skips)
            if (this->lastN != -1 && N > this->lastN + 1) {
                this->lostPackets += (N - this->lastN - 1);
            }
            this->lastN = N;

            // record last heartbeat time
            this->lastHeartbeatTime = now;

            // build response dynamically
            static char respBuffer[128];
            //formatted text into a buffer, prevents buffer overflow by specifying the maximum number of bytes to write
            snprintf(respBuffer, sizeof(respBuffer), "Heartbeat ACK, N=%d, Lost=%d, Latency=%lldms", N, this->lostPackets, latency);

            if (verbose) {
                std::cout << "Heartbeat received → N=" << N << ", Lost=" << this->lostPackets << ", Latency=" << latency << " ms" << std::endl;
            }

            return respBuffer;
        } else {
            return "Malformed Heartbeat";
        }
    }

    ~UDPSocketServer(){
        cleanup();
    };

    void cleanup(){
        close(this->serverSocket);
        delete[] this->buffer;
        this->buffer = nullptr;
    }
};



int main(int argc, char *argv[]) {

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <port> [address] [-v] [--buffsize <bytes>] [--neterr <percent>] [--heartbeat <0|1>] [--heartms <ms>]" << std::endl;
        return 1;
    }

    //* Required: port
    int port = std::stoi(argv[1]);

    //* Optional args
    std::string address = "0.0.0.0"; // all interfaces by default
    bool verbose = false;
    int buffsize = 1024; // default buffer size
    int netErrorPercent = 0; // default: no simulated packet loss
    bool heartbeatEnabled = false;
    int heartbeatMs = 3000; // default heartbeat interval

    //* Parse remaining args
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-v") {
            verbose = true;
        } else if (arg == "--buffsize" && i + 1 < argc) {
            buffsize = std::stoi(argv[++i]);
        } else if (arg == "--neterr" && i + 1 < argc) {
            netErrorPercent = std::stoi(argv[++i]);
        } else if (arg == "--heartbeat" && i + 1 < argc) {
            heartbeatEnabled = (std::stoi(argv[++i]) != 0);
        } else if (arg == "--heartms" && i + 1 < argc) {
            heartbeatMs = std::stoi(argv[++i]);
        } else if (address == "0.0.0.0" && arg != "-v") {
            address = arg;
        }
    }

    //* server
    UDPSocketServer server = UDPSocketServer(port, address, verbose, buffsize, netErrorPercent, heartbeatEnabled, heartbeatMs);

    if (server.createSocket() > 0)
    {
        return 1;
    }

    server.run();

    return 0;
}