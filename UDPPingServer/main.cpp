#include <cstring>        // strings
#include <iostream>       // output (cout, cin)
#include <netinet/in.h>   // socket struct and utils (sockaddr_in)
#include <sys/socket.h>   // create socket
#include <unistd.h>       // posix close(), read(), write()
#include <arpa/inet.h>    // inet_pton()
#include <thread>         // std::thread for heartbeat
#include <chrono>         // std::chrono for timing
#include <cstdlib>        // rand(), srand()
#include <ctime>          // time()

int main(int argc, char *argv[]) {

    //* Setting args
    //* Usage: ./udp_server <port> [address] [-v] [--buffsize <bytes>] [--neterr <percent>] [--heartbeat <0|1>] [--heartms <ms>]
    //* Exemple: ./udp_server 8080 -v --buffsize 1024 --neterr 0.25 --heartbeat 1 --heartms 200

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
            address = arg;  // treat first non-flag as address
        }
    }

    //* Display configuration summary
    if (verbose) {
        std::cout << "=== UDP SERVER CONFIG ===" << std::endl;
        std::cout << "Address: " << address << std::endl;
        std::cout << "Port: " << port << std::endl;
        std::cout << "Buffer size: " << buffsize << " bytes" << std::endl;
        std::cout << "Network error simulation: " << netErrorPercent << "%" << std::endl;
        std::cout << "Heartbeat: " << (heartbeatEnabled ? "ON" : "OFF") << " (" << heartbeatMs << " ms)" << std::endl;
        std::cout << "Verbose mode enabled\n" << std::endl;
    }

    // ! asdasda
    //* Create the socket
    // AF_INET → IPv4 address family
    // SOCK_DGRAM → UDP protocol (unlike SOCK_STREAM for TCP)
    // 0 → choose default protocol for UDP
    int serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
    // verify if socket was created
    if (serverSocket < 0) {
        std::cerr << "Error: failed to create socket.";
        return 1;
    }

    //* Configure the server address
    sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress)); // Clear structure memory

    serverAddress.sin_family = AF_INET; // IPv4
    serverAddress.sin_port = htons(port); // Host to Network Short (host byte order to network byte order)

    // Set network interface to listen
    if (inet_pton(AF_INET, address.c_str(), &serverAddress.sin_addr) <= 0) {
        std::cerr << "Invalid address: " << address << std::endl;
        close(serverSocket);
        return 1;
    }

    //* Bind the socket
    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Error: binding failed." << std::endl;
        close(serverSocket);
        return 1;
    }

    std::cout << "UDP server listening on " << address << ":" << port << std::endl;

    //* Prepare to receive messages
    char *buffer = new char[buffsize]; // dynamic buffer
    sockaddr_in clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);

    //* Random for network error
    srand(static_cast<unsigned>(time(nullptr)));

    //* Heartbeat thread
    std::thread heartbeatThread;
    bool running = true;

    if (heartbeatEnabled) {
        heartbeatThread = std::thread([&]() {
            while (running) {
                std::cout << "[HEARTBEAT] Server alive at "
                          << std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count()
                          << " ms" << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(heartbeatMs));
            }
        });
    }

    //* Main receive loop
    while (true) {
        memset(buffer, 0, buffsize);

        ssize_t bytesReceived = recvfrom(
            serverSocket,
            buffer,
            buffsize - 1,
            0,
            (struct sockaddr*)&clientAddress,
            &clientAddressLen
        );

        if (bytesReceived < 0) {
            std::cerr << "Error receiving data." << std::endl;
            continue;
        }

        buffer[bytesReceived] = '\0';

        // Simulate network error (packet loss)
        int randomValue = rand() % 100;
        if (randomValue < netErrorPercent) {
            if (verbose)
                std::cout << "[NETERR] Simulated packet loss for message: " << buffer << std::endl;
            continue;  // Drop message
        }

        std::cout << "Message from client: " << buffer << std::endl;

        // send a response back to client
        const char* response = "received by server.";
        sendto(
            serverSocket,
            response,
            strlen(response),
            0,
            (struct sockaddr*)&clientAddress,
            clientAddressLen
        );
    }

    //* Cleanup (never reached in loop, but safe practice)
    running = false;
    if (heartbeatThread.joinable()) heartbeatThread.join();
    close(serverSocket);
    delete[] buffer;

    return 0;
}