/*
 * Usage: ./icmp_ping [address] [-v] [--buffsize <bytes>] [--pingtimes <n>] [--timeout <ms>] [--payload <bytes>]
 * Example: ./icmp_ping 8.8.8.8 -v --buffsize 1024 --pingtimes 10 --timeout 1000 --payload 56
 */

#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

class ICMPTraceroute {
private:
    int sock;
    sockaddr_in dest{};
    std::string address;
    int maxHops = 30;
    int timeoutMs = 1000;
    int payloadSize = 32;
    int pid = getpid() & 0xFFFF;
    bool verbose = false;

public:
    ICMPTraceroute(
        std::string addr,
        int maxHops = 30,
        int timeoutMs = 1000,
        bool verbose = false
    ) :
        address(addr),
        maxHops(maxHops),
        timeoutMs(timeoutMs),
        verbose(verbose)
    {
        this->pid = getpid() & 0xFFFF;
        this->sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (this->sock < 0) {
            perror("socket");
            exit(EXIT_FAILURE);
        }

        hostent* host = gethostbyname(addr.c_str());
        if (!host) {
            std::cerr << "Host not found: " << addr << std::endl;
            exit(EXIT_FAILURE);
        }

        this->dest.sin_family = AF_INET;
        this->dest.sin_addr = *reinterpret_cast<in_addr*>(host->h_addr);
    }

    ~ICMPTraceroute() { close(this->sock); }

private:
    static uint16_t checksum(const void* buf, int len) {
        const uint8_t* data = static_cast<const uint8_t*>(buf);
        uint32_t sum = 0;
        for (int i = 0; i + 1 < len; i += 2)
            sum += (data[i] << 8) | data[i + 1];
        if (len & 1)
            sum += data[len - 1] << 8;
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return htons(~sum & 0xFFFF);
    }

    int buildPacket(uint8_t* buf, uint16_t seq) {
        icmphdr hdr{};
        hdr.type = ICMP_ECHO;
        hdr.code = 0;
        hdr.un.echo.id = htons(pid);
        hdr.un.echo.sequence = htons(seq);
        hdr.checksum = 0;

        memcpy(buf, &hdr, sizeof(hdr));

        // timestamp for RTT
        auto now = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        uint64_t ts = htobe64(now);
        memcpy(buf + sizeof(hdr), &ts, sizeof(ts));

        // Fill payload
        if (payloadSize > 8)
            memset(buf + sizeof(hdr) + 8, 0xAB, payloadSize - 8);

        reinterpret_cast<icmphdr*>(buf)->checksum = checksum(buf, sizeof(hdr) + payloadSize);
        return sizeof(hdr) + payloadSize;
    }

    bool sendEcho(uint16_t seq, int ttl) {
        // Set TTL for this hop
        if (setsockopt(this->sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            perror("setsockopt TTL");
            return false;
        }

        std::vector<uint8_t> buf(sizeof(icmphdr) + this->payloadSize);
        buildPacket(buf.data(), seq);

        ssize_t sent = sendto(this->sock, buf.data(), buf.size(), 0, (sockaddr*)&this->dest, sizeof(this->dest));
        if (sent < 0) {
            if (this->verbose) perror("sendto");
            return false;
        }

        return true;
    }

    int receiveReply(double& rtt_ms, std::string& hopAddr, const std::chrono::high_resolution_clock::time_point& send_time) {
        std::vector<uint8_t> buf(1024);
        sockaddr_in from{};
        socklen_t addrlen = sizeof(from);

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(this->sock, &fds);
        timeval tv{this->timeoutMs / 1000, (this->timeoutMs % 1000) * 1000};

        int rv = select(this->sock + 1, &fds, nullptr, nullptr, &tv);
        if (rv == 0) return 1; // timeout
        if (rv < 0) return 2; // error

        ssize_t n = recvfrom(this->sock, buf.data(), buf.size(), 0, (sockaddr*)&from, &addrlen);
        if (n <= 0) return 2;

        hopAddr = inet_ntoa(from.sin_addr);

        auto recv_time = std::chrono::high_resolution_clock::now();
        rtt_ms = double((std::chrono::duration_cast<std::chrono::microseconds>(recv_time - send_time).count()))/1000;

        int ihl = reinterpret_cast<iphdr*>(buf.data())->ihl * 4;
        icmphdr* icmp = reinterpret_cast<icmphdr*>(buf.data() + ihl);

        if (icmp->type == ICMP_TIME_EXCEEDED) {
            return 3; // hop, but not destination
        } else if (icmp->type == ICMP_ECHOREPLY) {
            return 0; // destination reached
        }

        return 4; // unknown response
    }

public:
    void run() {
        std::cout << "Tracing route to " << this->address << " (" << inet_ntoa(this->dest.sin_addr) << "), max " << this->maxHops << " hops\n";

        for (int ttl = 1; ttl <= maxHops; ++ttl) {
            std::cout << ttl << "  ";
            fflush(stdout);

            double rtt = 0.0;
            std::string hopAddr;
            uint16_t seq = ttl;

            if (!sendEcho(seq, ttl)) {
                std::cout << "Send error\n";
                continue;
            }
            auto send_time = std::chrono::high_resolution_clock::now();

            int result = receiveReply(rtt, hopAddr, send_time);

            if (result == 1) {
                std::cout << "* (timeout)\n";
            } else if (result == 2) {
                std::cout << "Socket error\n";
            } else if (result == 3) {
                std::cout << hopAddr << "  " << rtt << " ms\n";
            } else if (result == 0) {
                std::cout << hopAddr << "  " << rtt << " ms  [destination reached]\n";
                break;
            } else {
                std::cout << "Unknown ICMP reply\n";
            }
        }
    }
};

int main(int argc, char* argv[]) {
    std::string address = "8.8.8.8";
    int maxHops = 30;
    int timeout = 1000;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--maxhops" && i + 1 < argc)
            maxHops = std::stoi(argv[++i]);
        else if (arg == "--timeout" && i + 1 < argc)
            timeout = std::stoi(argv[++i]);
        else if (arg == "-v")
            verbose = true;
        else if (arg[0] != '-')
            address = arg;
    }

    ICMPTraceroute tracer(address, maxHops, timeout, verbose);
    tracer.run();

    return 0;
}