/*
 * Usage: ./icmp_ping [address] [-v] [--buffsize <bytes>] [--pingtimes <n>] [--timeout <ms>] [--payload <bytes>]
 * Example: sudo ./icmp_ping 8.8.8.8 -v --buffsize 1024 --pingtimes 10 --timeout 1000 --payload 56
 */

#include <arpa/inet.h> // inet_pton()
#include <chrono> // std::chrono for time
#include <csignal>
#include <cstring> // strings
#include <cerrno> // print message immediately - unbuffered
#include <iomanip>
#include <iostream>  // output (cout, cin)
#include <netinet/ip_icmp.h> // ICMP struct
#include <netinet/in.h> // socket struct and utils (sockaddr_in)
#include <string> // more string utils
#include <sys/select.h>
#include <sys/socket.h> // create socket
#include <unistd.h> // posix close(), read(), write()
#include <vector> // std::vector
#include <atomic> // atomic types ensure safe access in multithreaded

class ICMPPing {
private:
    int sock;
    std::string address = "127.0.0.1";
    bool verbose = false;
    int buffsize = 1024;
    int timeoutMs = 1000;
    int pingTimes = 4;
    int payloadSize = 56;

    sockaddr_in dest{};
    uint16_t pid;

public:
    ICMPPing(
        const std::string& addr,
        bool verbose,
        int buffsize,
        int pingTimes,
        int timeoutMs,
        int payloadSize
    ) :
        address(addr),
        verbose(verbose),
        buffsize(buffsize),
        timeoutMs(timeoutMs),
        pingTimes(pingTimes),
        payloadSize(payloadSize)
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
            std::cout << "Ping times: " << this->pingTimes << std::endl;
            std::cout << "Timeout: " << this->timeoutMs << " ms" << std::endl;
            std::cout << "Payload size: " << this->payloadSize << " bytes" << std::endl;
            std::cout << "Verbose mode enabled" << std::endl;
            std::cout << "========================" << std::endl;
        }
    }

    int createSocket() {
        //* Create socket
        // AF_INET → IPv4 address family
        // SOCK_RAW → Raw socket (used for low-level protocols like ICMP)
        // 1 or IPPROTO_ICMP → Protocol number for ICMP packets
        this->sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        // Verify if socket was created
        if (sock < 0) {
            std::cerr << "Error: failed to create socket." << std::endl << "May requires root privileges.";
            return 1;
        }

        // Set a real buffer fot the socket
        if (setsockopt(this->sock, SOL_SOCKET, SO_RCVBUF, &this->buffsize, sizeof(this->buffsize)) < 0 && this->verbose) {
            perror("setsockopt SO_RCVBUF");
        }

        this->dest.sin_family = AF_INET; // IPv4
        // dont need port

        // Set IP to listen
        if (inet_pton(AF_INET, this->address.c_str(), &this->dest.sin_addr) != 1) {
            std::cerr << "Invalid address: " << this->address << std::endl;
            return 1;
        }
        return 0;
    }

private:
    //* ICMP checksum
    // 16-bit value used to verify data integrity of header + payload.
    // It's the one's complement of the one's complement sum of all 16-bit words.
    static uint16_t checksum(const void* buf, int len) {
        // raw data
        const uint8_t* data = static_cast<const uint8_t*>(buf);
        // 32-bit to prevents overflow
        uint32_t sum = 0;
        // Add two bytes at a time
        for (int i = 0; i + 1 < len; i += 2) {
            // Combine two consecutive bytes into one 16-bit word and add to sum
            sum += (data[i] << 8) | data[i + 1];
        }
        // If data length is odd, add the last remaining byte
        if (len & 1) sum += data[len - 1] << 8;  // Shift left to make it the high byte of a 16-bit word
        // Test if bigger than 16 bits
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16); //carry bits from the upper 16 bits into the lower 16 bits
        }
        // htons() converts from host byte order to network byte order (big-endian)
        return htons(~sum & 0xFFFF);
    }

    // Build an ICMP Echo Request (ping) packet and return packet size
    int buildPacket(uint8_t* buf, uint16_t seq) {
        icmphdr hdr{}; // ICMP header structure
        hdr.type = ICMP_ECHO; // type = 8 -> Echo Request
        hdr.code = 0; // Code for Echo Request (no subcodes used)

        // Identifier field (used to match replies with requests), usually set to the process ID
        hdr.un.echo.id = htons(pid); //htons() converts to network byte order (big-endian)
        hdr.un.echo.sequence = htons(seq); // Sequence number (increments with each ping)
        hdr.checksum = 0; // Calc after

        // Copy the header to  buffer
        memcpy(buf, &hdr, sizeof(hdr));

        // Get current time since epoch, in microseconds
        long long now = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        uint64_t ts = htobe64(now); // Timestamp to big-endian 64-bit integer

        // Copy timestamp after header
        memcpy(buf + sizeof(hdr), &ts, sizeof(ts));

        // fill payload with 0xAA
        if (this->payloadSize > 8) memset(buf + sizeof(hdr) + 8, 0xAA, this->payloadSize - 8);

        reinterpret_cast<icmphdr*>(buf)->checksum = checksum(buf, sizeof(hdr) + this->payloadSize); //calc checksum

        // Return total number of bytes written to buffer
        return sizeof(hdr) + this->payloadSize;
    }

    // Send echo request
    bool sendEcho(uint16_t seq) {
        std::vector<uint8_t> buf(sizeof(icmphdr) + this->payloadSize); //Allocate buffer
        buildPacket(buf.data(), seq);
        ssize_t sent = sendto(
            this->sock,
            buf.data(), // data
            buf.size(),
            0, // Optional flags (MSG_DONTWAIT for non-blocking)
            (sockaddr*)&this->dest,
            sizeof(this->dest)
        );
        if (sent < 0 && this->verbose) perror("sendto");
        return sent >= 0;
    }

int receiveEcho(uint16_t seq, int& rtt_ms) {
    std::vector<uint8_t> buf(this->buffsize); // Alocate buffer
    // Structure to sender address
    sockaddr_in from{};
    socklen_t addrlen = sizeof(from);

    // Process-unique identifier (handle) for a file or other input/output
    fd_set fds;
    FD_ZERO(&fds); // Clear file descriptor set (handle)
    FD_SET(this->sock, &fds); // Add ICMP socket to watch list

    // Convert timeout from milliseconds to timeval struct (seconds + microseconds)
    timeval tv{
        this->timeoutMs / 1000, // seconds
        (this->timeoutMs % 1000) * 1000 // microseconds
    };

    // Wait data or timeout
    int rv = select(this->sock + 1, &fds, nullptr, nullptr, &tv);
    if (rv <= 0) return 1; // 0 -> timeout, 0< -> error

    // recive data and sender info
    ssize_t n = recvfrom(this->sock, buf.data(), buf.size(), 0, (sockaddr*)&from, &addrlen);
    if (n <= 0) return 1; // 0 -> no data, n < 0 -> error

    // The IP header length (IHL), multiply by 4 to get bytes
    int ihl = reinterpret_cast<iphdr*>(buf.data())->ihl * 4;
    // Move pointer to the ICMP header
    icmphdr* icmp = reinterpret_cast<icmphdr*>(buf.data() + ihl);

    if (
        icmp->type == ICMP_ECHOREPLY && // echo replay
        ntohs(icmp->un.echo.id) == this->pid && // verify PID
        ntohs(icmp->un.echo.sequence) == seq // seq must match
    ) {
        uint64_t ts_sent;
        memcpy(&ts_sent, buf.data() + ihl + sizeof(icmphdr), 8); //Extract the timestamp from the ICMP payload
        ts_sent = be64toh(ts_sent); // big-endian to host byte order

        // calc RTT (convert microseconds → milliseconds)
        long long now = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        rtt_ms = int((now - ts_sent) / 1000);

        return 0;
    } else { // Handel timeouts and erros
        switch (icmp->type) {
            case ICMP_DEST_UNREACH: {
                std::string reason;
                switch (icmp->code) {
                    case 0: reason = "Destination Network Unreachable"; break;
                    case 1: reason = "Destination Host Unreachable"; break;
                    case 2: reason = "Protocol Unreachable"; break;
                    case 3: reason = "Port Unreachable"; break;
                    case 4: reason = "Fragmentation Needed"; break;
                    case 5: reason = "Source Route Failed"; break;
                    default: reason = "Destination Unreachable (Other)"; break;
                }
                std::cout << "ICMP Error: " << reason << std::endl;
                break;
            }
            case ICMP_TIME_EXCEEDED:
                std::cout << "ICMP Error: Time Exceeded" << std::endl; break;
            case ICMP_REDIRECT:
                std::cout << "ICMP Error: Redirect Message" << std::endl; break;
            default:
                std::cout << "ICMP Error: Unknown type (" << int(icmp->type) << ")" << std::endl; break;
        }
    }

    return 1;
}

public:
    // Ping loop
    void startPingLoop() {
        int lostCount = 0;
        long long minRTT = 1e9;
        long long maxRTT = 0;
        long long sumRTT = 0;

        for (int i = 0; i < this->pingTimes; i++) {
            uint16_t seq = i + 1;
            sendEcho(seq);
            int rtt = -1;
            if (receiveEcho(seq, rtt)) {
                lostCount++;
            } else {
                std::cout << "Ping " << seq << " Reply OK | RTT: " << rtt << " ms\n";
                sumRTT += rtt;
                if (rtt < minRTT) minRTT = rtt;
                if (rtt > maxRTT) maxRTT = rtt;
            }
        }

        std::cout << std::endl << "Ping finished. Lost: " << lostCount << "/" << this->pingTimes << " (" << 100.0 * lostCount / this->pingTimes << "%)" << std::endl;
        if (this->pingTimes - lostCount > 0) {
            std::cout << "RTT min/avg/max = " << minRTT << "/" << (sumRTT / (this->pingTimes - lostCount)) << "/" << maxRTT << " ms" << std::endl;
        }
    }


    void run() {
        displayInfo();
        startPingLoop();
    }

    void cleanup() {
        if (sock >= 0) close(sock);
    }
};

int main(int argc, char** argv) {
    std::string address = "127.0.0.1";
    bool verbose = false;
    int buffsize = 1024;
    int pingTimes = 4;
    int timeoutMs = 1000;
    int payloadSize = 56;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v") verbose = true;
        else if (arg == "--buffsize" && i + 1 < argc) buffsize = std::stoi(argv[++i]);
        else if (arg == "--pingtimes" && i + 1 < argc) pingTimes = std::stoi(argv[++i]);
        else if (arg == "--timeout" && i + 1 < argc) timeoutMs = std::stoi(argv[++i]);
        else if (arg == "--payload" && i + 1 < argc) payloadSize = std::stoi(argv[++i]);
        else if (address == "127.0.0.1" && arg[0] != '-') address = arg;
        else {
            std::cerr << "Unknown argument: " << arg << "\n";
            return 1;
        }
    }

    ICMPPing ping(address, verbose, buffsize, pingTimes, timeoutMs, payloadSize);
    if (ping.createSocket()) return 1;

    ping.run();
    return 0;
}