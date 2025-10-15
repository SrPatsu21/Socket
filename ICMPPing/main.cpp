/*
 * Usage: ./icmp_client [address] [-v] [--buffsize <bytes>] [--pingtimes <n>] [--timeout <ms>] [--heartbeat <0|1>] [--heartms <ms>] [--payload <bytes>]
 * Example: ./icmp_client 8.8.8.8 -v --buffsize 1024 --pingtimes 10 --timeout 1000 --heartbeat 1 --heartms 1000 --payload 56
 */

#include <arpa/inet.h> // inet_pton()
#include <chrono>
#include <csignal>
#include <cstring> // strings
#include <cerrno>
#include <iomanip>
#include <iostream>  // output (cout, cin)
#include <netinet/ip_icmp.h> // ICMP struct
#include <netinet/in.h> // socket struct and utils (sockaddr_in)
#include <string> // more string utils
#include <sys/select.h>
#include <sys/socket.h> // create socket
#include <thread>
#include <unistd.h>
#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>

class ICMPPing {
private:
    int sock = -1;
    std::string address = "127.0.0.1";
    bool verbose = false;
    int buffsize = 1024;
    int timeoutMs = 1000;
    int pingTimes = 4;
    bool heartbeatEnabled = false;
    int heartbeatMs = 1000;
    int payloadSize = 56;
    bool pingEnabled = true;

    sockaddr_in dest{};
    uint16_t pid;
    std::atomic<bool> running;
    std::atomic<bool> waitingPing;
    std::mutex mtx;
    std::condition_variable cv;
    std::atomic<int> heartbeatCount;

public:
    ICMPPing(
        const std::string& addr,
        bool verbose,
        int buffsize,
        int pingTimes,
        int timeoutMs,
        bool pingEnabled,
        bool heartbeatEnabled,
        int heartbeatMs,
        int payloadSize
    ) :
        address(addr),
        verbose(verbose),
        buffsize(buffsize),
        pingTimes(pingTimes),
        timeoutMs(timeoutMs),
        pingEnabled(pingEnabled),
        heartbeatEnabled(heartbeatEnabled),
        heartbeatMs(heartbeatMs),
        payloadSize(payloadSize),
        running(true),
        waitingPing(false),
        heartbeatCount(0)
    {
        this->pid = static_cast<uint16_t>(getpid() & 0xFFFF);
    }

    ~ICMPPing() {
        cleanup();
    }

    void displayInfo() {
        if (this->verbose) {
            std::cout << "=== ICMP PING CONFIG ===" << std::endl;
            std::cout << "Target Address: " << this->address << std::endl;
            std::cout << "Buffer size: " << this->buffsize << " bytes" << std::endl;
            std::cout << "Ping: " << (this->pingEnabled ? "ON" : "OFF") << " (" << this->pingTimes << " times)" << std::endl;
            std::cout << "Timeout: " << this->timeoutMs << " ms" << std::endl;
            std::cout << "Heartbeat: " << (this->heartbeatEnabled ? "ON" : "OFF") << " (" << heartbeatMs << " ms)" << std::endl;
            std::cout << "Payload size: " << this->payloadSize << " bytes" << std::endl;
            std::cout << "Verbose mode enabled" << std::endl;
            std::cout << "========================" << std::endl;
        }
    }

    int createSocket() {
        this->sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) {
            perror("socket");
            std::cerr << "Requires root privileges (CAP_NET_RAW)\n";
            return false;
        }
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffsize, sizeof(buffsize)) < 0 && verbose) {
            perror("setsockopt SO_RCVBUF");
        }

        dest.sin_family = AF_INET;
        if (inet_pton(AF_INET, address.c_str(), &dest.sin_addr) != 1) {
            std::cerr << "Invalid address: " << address << "\n";
            return false;
        }
        return true;
    }

private:
    // Compute ICMP checksum
    static uint16_t checksum(const void* buf, int len) {
        const uint8_t* data = static_cast<const uint8_t*>(buf);
        uint32_t sum = 0;
        for (int i = 0; i + 1 < len; i += 2) sum += (data[i] << 8) | data[i+1];
        if (len & 1) sum += data[len - 1] << 8;
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        return htons(~sum & 0xFFFF);
    }

    // Build ICMP echo request packet
    int buildPacket(uint8_t* buf, uint16_t seq) {
        icmphdr hdr{};
        hdr.type = ICMP_ECHO;
        hdr.code = 0;
        hdr.un.echo.id = htons(pid);
        hdr.un.echo.sequence = htons(seq);
        hdr.checksum = 0;

        memcpy(buf, &hdr, sizeof(hdr));

        auto now = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        uint64_t ts = htobe64(now);
        memcpy(buf + sizeof(hdr), &ts, sizeof(ts));

        if (payloadSize > 8)
            memset(buf + sizeof(hdr) + 8, 0xAA, payloadSize - 8);

        reinterpret_cast<icmphdr*>(buf)->checksum = checksum(buf, sizeof(hdr) + payloadSize);
        return sizeof(hdr) + payloadSize;
    }

    // Send ICMP echo request
    bool sendEcho(uint16_t seq) {
        std::vector<uint8_t> buf(sizeof(icmphdr) + payloadSize);
        buildPacket(buf.data(), seq);
        ssize_t sent = sendto(sock, buf.data(), buf.size(), 0, (sockaddr*)&dest, sizeof(dest));
        if (sent < 0 && verbose) perror("sendto");
        return sent >= 0;
    }

    // Receive ICMP echo reply
    bool receiveEcho(uint16_t seq, int& rtt_ms) {
        std::vector<uint8_t> buf(buffsize);
        sockaddr_in from{};
        socklen_t addrlen = sizeof(from);

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};

        int rv = select(sock + 1, &fds, nullptr, nullptr, &tv);
        if (rv <= 0) return false;

        ssize_t n = recvfrom(sock, buf.data(), buf.size(), 0, (sockaddr*)&from, &addrlen);
        if (n <= 0) return false;

        int ihl = reinterpret_cast<iphdr*>(buf.data())->ihl * 4;
        icmphdr* icmp = reinterpret_cast<icmphdr*>(buf.data() + ihl);

        if (icmp->type == ICMP_ECHOREPLY && ntohs(icmp->un.echo.id) == pid && ntohs(icmp->un.echo.sequence) == seq) {
            uint64_t ts_sent;
            memcpy(&ts_sent, buf.data() + ihl + sizeof(icmphdr), 8);
            ts_sent = be64toh(ts_sent);
            auto now = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()).count();
            rtt_ms = int((now - ts_sent) / 1000);
            return true;
        }
        return false;
    }

public:
    // Ping loop
    void startPingLoop() {
        if (!pingEnabled) return;

        std::thread([this]() {
            int lostCount = 0;
            long long minRTT = 1e9, maxRTT = 0, sumRTT = 0;

            for (int i = 0; i < pingTimes && running; i++) {
                uint16_t seq = i + 1;
                sendEcho(seq);

                int rtt = -1;
                if (!receiveEcho(seq, rtt)) {
                    lostCount++;
                    std::cout << "Ping " << seq << " Timeout\n";
                } else {
                    std::cout << "Ping " << seq << " Reply OK | RTT: " << rtt << " ms\n";
                    sumRTT += rtt;
                    if (rtt < minRTT) minRTT = rtt;
                    if (rtt > maxRTT) maxRTT = rtt;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(heartbeatMs));
            }

            std::cout << "\nPing finished. Lost: " << lostCount << "/" << pingTimes
                      << " (" << 100.0 * lostCount / pingTimes << "%)\n";
            if (pingTimes - lostCount > 0) {
                std::cout << "RTT min/avg/max = " << minRTT << "/" << (sumRTT / (pingTimes - lostCount)) << "/" << maxRTT << " ms\n";
                if (!this->heartbeatEnabled)
                {
                    this->running = false;
                }
            }

        }).detach();

    }

    // Heartbeat loop
    void startHeartbeatLoop() {
        if (!heartbeatEnabled) return;

        std::thread([this]() {
            while (running) {
                int n = heartbeatCount++;
                std::cout << "Heartbeat " << n << " sent\n";
                std::this_thread::sleep_for(std::chrono::milliseconds(heartbeatMs));
            }
        }).detach();
    }

    void run() {
        displayInfo();
        startHeartbeatLoop();
        startPingLoop();

        // Keep main thread alive
        while (running) std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    void cleanup() {
        if (sock >= 0) close(sock);
        running = false;
    }
};

int main(int argc, char** argv) {
    std::string address = "127.0.0.1";
    bool verbose = false;
    int buffsize = 1024;
    int pingTimes = 4;
    int timeoutMs = 1000;
    bool pingEnabled = true;
    bool heartbeatEnabled = false;
    int heartbeatMs = 1000;
    int payloadSize = 56;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v") verbose = true;
        else if (arg == "--buffsize" && i + 1 < argc) buffsize = std::stoi(argv[++i]);
        else if (arg == "--pingtimes" && i + 1 < argc) pingTimes = std::stoi(argv[++i]);
        else if (arg == "--timeout" && i + 1 < argc) timeoutMs = std::stoi(argv[++i]);
        else if (arg == "--heartbeat" && i + 1 < argc) heartbeatEnabled = std::stoi(argv[++i]) != 0;
        else if (arg == "--heartms" && i + 1 < argc) heartbeatMs = std::stoi(argv[++i]);
        else if (arg == "--payload" && i + 1 < argc) payloadSize = std::stoi(argv[++i]);
        else if (address == "127.0.0.1" && arg[0] != '-') address = arg;
        else {
            std::cerr << "Unknown argument: " << arg << "\n";
            return 1;
        }
    }

    ICMPPing ping(address, verbose, buffsize, pingTimes, timeoutMs, pingEnabled, heartbeatEnabled, heartbeatMs, payloadSize);
    if (!ping.createSocket()) return 1;

    ping.run();
    return 0;
}