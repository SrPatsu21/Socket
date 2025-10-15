#include <arpa/inet.h>
#include <chrono>
#include <csignal>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace std;
using namespace std::chrono;

class ICMPPing {
public:
    struct Config {
        string address = "127.0.0.1";
        bool verbose = false;
        int buffsize = 1024;
        int timeoutMs = 1000;
        int pingTimes = 4;
        bool heartbeatEnabled = false;
        int heartbeatMs = 1000;
        int payloadSize = 56;
    };

private:
    Config cfg;
    int sock = -1;
    sockaddr_in dest{};
    uint16_t pid;
    bool stopRequested = false;

public:
    explicit ICMPPing(const Config& config) : cfg(config) {
        pid = static_cast<uint16_t>(getpid() & 0xFFFF);
        setupSocket();
        resolveAddress();
        signal(SIGINT, signalHandler);
        instance = this;
    }

    ~ICMPPing() {
        if (sock >= 0) close(sock);
    }

    static ICMPPing* instance;
    static void signalHandler(int) {
        if (instance) instance->stopRequested = true;
    }

    void run() {
        if (cfg.heartbeatEnabled)
            runHeartbeat();
        else
            runOnce();
    }

private:
    void setupSocket() {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) {
            perror("socket");
            cerr << "Note: requires root privileges (CAP_NET_RAW)\n";
            exit(1);
        }
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &cfg.buffsize, sizeof(cfg.buffsize)) < 0) {
            if (cfg.verbose) perror("setsockopt SO_RCVBUF");
        }
    }

    void resolveAddress() {
        dest.sin_family = AF_INET;
        if (inet_pton(AF_INET, cfg.address.c_str(), &dest.sin_addr) != 1) {
            cerr << "Invalid IPv4 address: " << cfg.address << "\n";
            exit(1);
        }
    }

    static uint16_t checksum(const void* buf, int len) {
        const uint8_t* data = static_cast<const uint8_t*>(buf);
        uint32_t sum = 0;
        for (int i = 0; i + 1 < len; i += 2) {
            uint16_t word = (uint16_t(data[i]) << 8) | uint16_t(data[i+1]);
            sum += word;
        }
        if (len & 1) sum += uint16_t(data[len - 1]) << 8;
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        return htons(~sum & 0xFFFF);
    }

    int buildPacket(uint8_t* buf, uint16_t seq) {
        struct icmphdr hdr{};
        hdr.type = ICMP_ECHO;
        hdr.code = 0;
        hdr.un.echo.id = htons(pid);
        hdr.un.echo.sequence = htons(seq);
        hdr.checksum = 0;

        memcpy(buf, &hdr, sizeof(hdr));

        auto now = duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch()).count();
        uint64_t ts = htobe64(now);
        memcpy(buf + sizeof(hdr), &ts, sizeof(ts));
        if (cfg.payloadSize > 8)
            memset(buf + sizeof(hdr) + 8, 0xAA, cfg.payloadSize - 8);

        int packetLen = sizeof(hdr) + cfg.payloadSize;
        uint16_t cs = checksum(buf, packetLen);
        reinterpret_cast<icmphdr*>(buf)->checksum = cs;
        return packetLen;
    }

    bool sendEcho(uint16_t seq) {
        vector<uint8_t> buf(sizeof(icmphdr) + cfg.payloadSize);
        int len = buildPacket(buf.data(), seq);
        ssize_t sent = sendto(sock, buf.data(), len, 0, (sockaddr*)&dest, sizeof(dest));
        if (sent < 0) {
            if (cfg.verbose) perror("sendto");
            return false;
        }
        return true;
    }

    bool receiveEcho(uint16_t seq, int& rtt_us, string& fromAddr) {
        vector<uint8_t> recvbuf(cfg.buffsize);
        sockaddr_in from{};
        socklen_t addrlen = sizeof(from);

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        timeval tv{cfg.timeoutMs / 1000, (cfg.timeoutMs % 1000) * 1000};

        int rv = select(sock + 1, &fds, nullptr, nullptr, &tv);
        if (rv <= 0) return false;

        ssize_t n = recvfrom(sock, recvbuf.data(), recvbuf.size(), 0, (sockaddr*)&from, &addrlen);
        if (n <= 0) return false;

        auto* ip = reinterpret_cast<iphdr*>(recvbuf.data());
        int ihl = ip->ihl * 4;
        auto* icmp = reinterpret_cast<icmphdr*>(recvbuf.data() + ihl);

        if (icmp->type == ICMP_ECHOREPLY && ntohs(icmp->un.echo.id) == pid && ntohs(icmp->un.echo.sequence) == seq) {
            if (n >= ihl + sizeof(icmphdr) + 8) {
                uint64_t ts_net;
                memcpy(&ts_net, recvbuf.data() + ihl + sizeof(icmphdr), 8);
                uint64_t ts_sent = be64toh(ts_net);
                auto now = duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch()).count();
                rtt_us = int(now - ts_sent);
            }
            char addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, addr, sizeof(addr));
            fromAddr = addr;
            return true;
        }
        return false;
    }

    void runOnce() {
        cout << "PING " << cfg.address << " (" << cfg.address << "): " << cfg.payloadSize << " data bytes\n";
        int sent = 0, received = 0;
        vector<int> rtts;

        for (int i = 0; i < cfg.pingTimes && !stopRequested; ++i) {
            uint16_t seq = i + 1;
            sendEcho(seq);
            sent++;

            int rtt_us = -1;
            string from;
            if (receiveEcho(seq, rtt_us, from)) {
                received++;
                rtts.push_back(rtt_us);
                cout << "Reply from " << from << ": seq=" << seq << " time=" << rtt_us / 1000.0 << " ms\n";
            } else {
                cout << "Request timed out for seq=" << seq << "\n";
            }

            if (i + 1 < cfg.pingTimes)
                this_thread::sleep_for(milliseconds(cfg.heartbeatMs));
        }

        printSummary(sent, received, rtts);
    }

    void runHeartbeat() {
        cout << "Starting heartbeat mode. Press Ctrl+C to stop.\n";
        uint16_t seq = 0;
        int sent = 0, received = 0;
        vector<int> rtts;

        while (!stopRequested) {
            seq++;
            sendEcho(seq);
            sent++;
            int rtt_us = -1;
            string from;
            if (receiveEcho(seq, rtt_us, from)) {
                received++;
                rtts.push_back(rtt_us);
                cout << "Reply from " << from << ": seq=" << seq << " time=" << rtt_us / 1000.0 << " ms\n";
            } else {
                cout << "Request timed out for seq=" << seq << "\n";
            }
            this_thread::sleep_for(milliseconds(cfg.heartbeatMs));
        }

        printSummary(sent, received, rtts);
    }

    void printSummary(int sent, int received, const vector<int>& rtts) {
        cout << "\n--- " << cfg.address << " ping statistics ---\n";
        int lost = sent - received;
        double loss = sent ? 100.0 * lost / sent : 0.0;
        cout << sent << " packets transmitted, " << received << " received, " 
             << fixed << setprecision(1) << loss << "% packet loss\n";
        if (!rtts.empty()) {
            double minv = 1e9, maxv = 0, sum = 0;
            for (auto v : rtts) {
                double ms = v / 1000.0;
                minv = min(minv, ms);
                maxv = max(maxv, ms);
                sum += ms;
            }
            cout << "rtt min/avg/max = " << minv << "/" << (sum / rtts.size()) << "/" << maxv << " ms\n";
        }
    }
};

// static instance
ICMPPing* ICMPPing::instance = nullptr;

int main(int argc, char** argv) {
    ICMPPing::Config cfg;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-v") cfg.verbose = true;
        else if (arg == "--buffsize" && i + 1 < argc) cfg.buffsize = stoi(argv[++i]);
        else if (arg == "--timeout" && i + 1 < argc) cfg.timeoutMs = stoi(argv[++i]);
        else if (arg == "--pingtimes" && i + 1 < argc) cfg.pingTimes = stoi(argv[++i]);
        else if (arg == "--heartbeat" && i + 1 < argc) cfg.heartbeatEnabled = stoi(argv[++i]) != 0;
        else if (arg == "--heartms" && i + 1 < argc) cfg.heartbeatMs = stoi(argv[++i]);
        else if (arg == "--payload" && i + 1 < argc) cfg.payloadSize = stoi(argv[++i]);
        else if (cfg.address == "127.0.0.1" && arg[0] != '-') cfg.address = arg;
        else {
            cerr << "Unknown arg: " << arg << "\n";
            return 1;
        }
    }

    ICMPPing ping(cfg);
    ping.run();
    return 0;
}
