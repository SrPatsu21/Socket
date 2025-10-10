#include <cstring> // strings
#include <iostream> // output (cout, cin)
#include <netinet/in.h> // socket struct and utils (sockaddr_in)
#include <sys/socket.h> // create socket
#include <unistd.h> // posix close(), read(), write()
#include <arpa/inet.h> // inet_pton()
#include <thread> // std::thread for heartbeat
#include <chrono> // std::chrono for time
#include <atomic> // atomic types ensure safe access in multithreaded

class UDPSocketClient
{
private:
    int port;
    std::string address;
    bool verbose;
    int buffsize;
    int pingTimes;
    int timeoutMs;
    bool pingEnabled;
    int heartbeatMs;
    bool heartbeatEnabled;
    std::atomic<int> heartbeatCount;
    // socket
    int clientSocket;
    char *buffer;
    sockaddr_in serverAddress;
public:
    UDPSocketClient(
        int port,
        std::string address = "127.0.0.1",
        bool verbose = false,
        int buffsize = 1024,
        int pingTimes = 10,
        int timeoutMs = 1000,
        bool pingEnabled = true,
        bool heartbeatEnabled = false,
        int heartbeatMs = 3000
    ) :
        port(port),
        address(address),
        verbose(verbose),
        buffsize(buffsize),
        pingTimes(pingTimes),
        timeoutMs(timeoutMs),
        pingEnabled(pingEnabled),
        heartbeatEnabled(heartbeatEnabled),
        heartbeatMs(heartbeatMs)
    {
        heartbeatCount = 0;
        displayInfo();
    }

    void displayInfo() {
        if (verbose) {
            std::cout << "=== UDP SERVER CONFIG ===" << std::endl;
            std::cout << "Server Address: " << address << std::endl;
            std::cout << "Server Port: " << port << std::endl;
            std::cout << "Buffer size: " << buffsize << " bytes" << std::endl;
            std::cout << "Ping: " << (pingEnabled ? "ON" : "OFF") << " (" << pingTimes << " times)" << std::endl;
            std::cout << "Timeout: " << timeoutMs << " ms" << std::endl;
            std::cout << "Heartbeat: " << (heartbeatEnabled ? "ON" : "OFF") << " (" << heartbeatMs << " ms)" << std::endl;
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
        std::cout << "Type 'exit' to quit.\n" << std::endl;
    }

    void startHeartbeatLoop()
    {
        if (!this->heartbeatEnabled)
            return;

        std::thread([this]() {
            while (true) {
                std::this_thread::sleep_for(std::chrono::milliseconds(heartbeatMs));

                int n = heartbeatCount++;
                long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                // Build heartbeat message
                char msg[128];
                snprintf(msg, sizeof(msg), "Heartbeat,%d,%lld", n, now);

                sendMessage(msg);

                if (verbose) std::cout << "Sent " << msg << std::endl;
            }
        }).detach();
    }

    void startPingLoop()
    {
        if (!this->heartbeatEnabled)
            return;

        std::thread([this]() {
            while (true) {
                std::this_thread::sleep_for(std::chrono::milliseconds(heartbeatMs));

                int n = heartbeatCount++;
                long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                // Build heartbeat message
                char msg[128];
                snprintf(msg, sizeof(msg), "Heartbeat,%d,%lld", n, now);

                sendMessage(msg);

                if (verbose) std::cout << "Sent " << msg << std::endl;
            }
        }).detach();
    }
    int sendMessage(const std::string &message)
    {
        ssize_t bytesSent = sendto(
            clientSocket,
            message.c_str(),
            message.size(),
            0,
            (struct sockaddr *)&serverAddress,
            sizeof(serverAddress));

        if (bytesSent < 0)
        {
            std::cerr << "Error: failed to send message." << std::endl;
            return 1;
        }

        char recvBuffer[1024];
        memset(recvBuffer, 0, sizeof(recvBuffer));

        socklen_t serverLen = sizeof(serverAddress);
        ssize_t bytesReceived = recvfrom(
            clientSocket,
            recvBuffer,
            sizeof(recvBuffer) - 1,
            0,
            (struct sockaddr *)&serverAddress,
            &serverLen);

        if (bytesReceived > 0)
        {
            recvBuffer[bytesReceived] = '\0';
            std::cout << "Server reply: " << recvBuffer << std::endl;
        }
        else
        {
            std::cerr << "No response from server." << std::endl;
        }
    }

    int run()
    {
        if (heartbeatEnabled) {
            startHeartbeatLoop();
        }
        if (PingEnabled)
        {
            startPingLoop();
        }

        return 0;
    }

    ~UDPSocketClient(){
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
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <port> [address] [-v] [--buffsize <bytes>] [--heartbeat <0|1>] [--heartms <ms>]" << std::endl;
        return 1;
    }

    int port = std::stoi(argv[1]);
    std::string address = "127.0.0.1";
    bool verbose = false;
    int buffsize = 1024;
    bool heartbeatEnabled = false;
    int heartbeatMs = 3000;

    for (int i = 2; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "-v")
            verbose = true;
        else if (arg == "--buffsize" && i + 1 < argc)
            buffsize = std::stoi(argv[++i]);
        else if (arg == "--heartbeat" && i + 1 < argc)
            heartbeatEnabled = (std::stoi(argv[++i]) != 0);
        else if (arg == "--heartms" && i + 1 < argc)
            heartbeatMs = std::stoi(argv[++i]);
        else if (address == "127.0.0.1" && arg != "-v")
            address = arg;
    }

    UDPSocketClient client(port, address, verbose, buffsize, heartbeatEnabled, heartbeatMs);

    if (client.createSocket() > 0) {
        return 1;
    }
    if (client.run() > 0) {
        return 1;
    }
    return 0;
}