/*
 * Setting args
 * Usage: ./udp_client <port> [address] [-v] [--buffsize <bytes>] [--ping <0|1>] [--pingtimes <n>] [--timeout <ms>] [--heartbeat <0|1>] [--heartms <ms>]
 * Exemple: ./udp_client 8080 127.0.0.1 -v --buffsize 1024 --ping 1 --pingtimes 10 --timeout 1000 --heartbeat 1 --heartms 1000
 * Exemple just ping: ./udp_client 8080 127.0.0.1 -v --buffsize 1024 --ping 1 --pingtimes 10 --timeout 1000
 * Exemple just hearbeat: ./udp_client 8080 127.0.0.1 -v --buffsize 1024 --ping 0 --heartbeat 1 --heartms 1000
 */

#include <cstring> // strings
#include <iostream> // output (cout, cin)
#include <netinet/in.h> // socket struct and utils (sockaddr_in)
#include <sys/socket.h> // create socket
#include <unistd.h> // posix close(), read(), write()
#include <arpa/inet.h> // inet_pton()
#include <condition_variable>
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


    std::atomic<bool> running;
    std::atomic<bool> waitingPing;
    std::mutex mtx;
    std::condition_variable cv;
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
        int heartbeatMs = 500
    ) :
        port(port),
        address(address),
        verbose(verbose),
        buffsize(buffsize),
        pingTimes(pingTimes),
        timeoutMs(timeoutMs),
        pingEnabled(pingEnabled),
        heartbeatMs(heartbeatMs),
        heartbeatEnabled(heartbeatEnabled),
        heartbeatCount(0),
        running(true),
        waitingPing(false)
    {
        displayInfo();
    }


    void displayInfo() {
        if (this->verbose) {
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
        this->serverAddress.sin_port = htons(this->port); // Host to Network Short (host byte order to network byte order)

        // Set IP to listen
        if (inet_pton(AF_INET, this->address.c_str(), &this->serverAddress.sin_addr) <= 0) {
            std::cerr << "Invalid address: " << this->address << std::endl;
            return 1;
        }

        std::cout << "UDP client started." << std::endl;
        return 0;
    }


    void receiveHandler() {
        this->buffer = new char[this->buffsize]; // dynamic buffer

        socklen_t serverLen = sizeof(this->serverAddress);

        // recvfrom() waits for a UDP packet and fills buffer + client info
        while (this->running) {
            memset(this->buffer, 0, this->buffsize);
            ssize_t bytesReceived = recvfrom(
                this->clientSocket,
                this->buffer,
                this->buffsize - 1, // Leave space for null terminator '\0'
                0, // Optional flags (MSG_DONTWAIT for non-blocking)
                (struct sockaddr *)&this->serverAddress, // Pointer to a structure that will be filled with the sender's (server's) IP address and port
                &serverLen //size of the server's address structure
            );

            if (bytesReceived < 0) {
                std::cerr << "Error receiving data." << std::endl;
            } else {
                this->buffer[bytesReceived] = '\0';
                std::string msg(this->buffer);

                if (msg.rfind("Heartbeat", 0) == 0) {
                    std::cout << "Heartbeat reply " << msg << std::endl;
                }else if (msg.rfind("Ping", 0) == 0) {
                    std::cout << "Ping reply " << msg << std::endl;
                    {
                        std::unique_lock<std::mutex> lock(this->mtx);
                        this->waitingPing = false;
                    }
                    this->cv.notify_all(); // release ping loop
                }
            }
        }
    }

    void startHeartbeatLoop()
    {
        if (!this->heartbeatEnabled) return;

        std::thread([this]() {
            while (true) {

                int n = this->heartbeatCount++;
                long long now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

                // Build heartbeat message
                char msg[128];
                snprintf(msg, sizeof(msg), "Heartbeat,%d,%lld", n, now);

                sendto(
                    this->clientSocket,
                    msg,
                    strlen(msg),
                    0, // Optional flags (MSG_DONTWAIT for non-blocking)
                    (struct sockaddr *)&this->serverAddress,
                    sizeof(this->serverAddress)
                );

                if (this->verbose) std::cout << msg << std::endl;

                std::this_thread::sleep_for(std::chrono::milliseconds(this->heartbeatMs));
            }
        }).detach();
    }

    void startPingLoop() {
        if (!this->pingEnabled) return;

        std::thread([this]() {
            long long minRTT = 1e9;
            long long maxRTT = 0;
            double averageRTT = 0;
            int lostCount = 0;
            for (int i = 0; i < this->pingTimes && this->running; i++) {
                const char *msg = "Ping";
                long long startTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

                {
                    std::unique_lock<std::mutex> lock(this->mtx);
                    this->waitingPing = true;
                }

                ssize_t sent = sendto(
                    this->clientSocket,
                    msg,
                    strlen(msg),
                    0, // Optional flags (MSG_DONTWAIT for non-blocking)
                    (struct sockaddr *)&this->serverAddress,
                    sizeof(this->serverAddress)
                );

                if (sent < 0) {
                    std::cerr << "Ping " << i + 1 << " Failed to send." << std::endl;
                }else
                {
                    // wait until reply or timeout
                    std::unique_lock<std::mutex> lock(this->mtx);
                    if (!cv.wait_for(lock, std::chrono::milliseconds(this->timeoutMs), [this] { return !this->waitingPing.load(); })) {
                        std::cerr << "Ping " << i + 1 << " Timeout — no reply." << std::endl;
                        lostCount++;
                    } else {
                        long long endTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                        long long latency = endTime - startTime;
                        std::cout << "Ping " << i + 1 << " Reply OK | Latency: " << latency << " ms" << std::endl;
                        averageRTT += latency;
                        if (minRTT > latency) minRTT = latency;
                        if (maxRTT < latency) maxRTT = latency;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(500)); // interval between pings
                }
            }
            std::cout << "\nPing test complete: " << this->pingTimes - lostCount << " received, " << lostCount << " lost (" << (100.0 * lostCount / pingTimes) << "% loss)" << std::endl;
            std::cout << "Max latency:" << maxRTT << " Min latency:" << minRTT << " average latency:" << (averageRTT/(this->pingTimes-lostCount)) << std::endl;
        }).detach();
    }

    int run() {
        std::thread receiver(&UDPSocketClient::receiveHandler, this);
        if (this->heartbeatEnabled) startHeartbeatLoop();
        if (this->pingEnabled) startPingLoop();

        receiver.join();
        return 1;
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
        std::cerr << "Usage: " << argv[0] << " <port> [address] [-v] [--buffsize <bytes>] [--ping <0|1>] [--pingtimes <n>] [--timeout <ms>] [--heartbeat <0|1>] [--heartms <ms>]" << std::endl;
        return 1;
    }

    //* Required: port
    int port = std::stoi(argv[1]);

    //* Optional args
    std::string address = "0.0.0.0"; // all interfaces by default
    bool verbose = false;
    int buffsize = 1024; // default buffer size
    int pingTimes = 10; // N pings
    int timeoutMs = 1000; // time to wait for response
    bool pingEnabled = true;
    bool heartbeatEnabled = false;
    int heartbeatMs = 500; // default heartbeat interval

    //* Parse remaining args
    for (int i = 2; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "-v")
            verbose = true;
        else if (arg == "--buffsize" && i + 1 < argc)
            buffsize = std::stoi(argv[++i]);
        else if (arg == "--ping" && i + 1 < argc)
            pingEnabled = (std::stoi(argv[++i]) != 0);
        else if (arg == "--pingtimes" && i + 1 < argc)
            pingTimes = std::stoi(argv[++i]);
        else if (arg == "--timeout" && i + 1 < argc)
            timeoutMs = std::stoi(argv[++i]);
        else if (arg == "--heartbeat" && i + 1 < argc)
            heartbeatEnabled = (std::stoi(argv[++i]) != 0);
        else if (arg == "--heartms" && i + 1 < argc)
            heartbeatMs = std::stoi(argv[++i]);
        else if (address == "0.0.0.0" && arg[0] != '-v')
            address = arg;
    }

    UDPSocketClient client( port, address, verbose, buffsize, pingTimes, timeoutMs, pingEnabled, heartbeatEnabled, heartbeatMs);

    if (client.createSocket() != 0) return 1;

    return client.run();
}