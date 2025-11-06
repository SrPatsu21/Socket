/*
 * Usage: ./icmp_traceroute [address] [-v] [--maxhops <n>] [--timeout <ms>] [--payloadSize <bytes>] [--buffsize <bytes>]
 * Example: sudo ./icmp_traceroute 8.8.8.8 -v --maxhops 30 --timeout 1000 --payloadSize 56 --buffsize 1024
 */

#include <iostream>  // output (cout, cin)
#include <vector> // std::vector
#include <chrono> // std::chrono for time
#include <cstring> // strings
#include <netinet/ip_icmp.h> // ICMP struct
#include <netinet/in.h> // socket struct and utils (sockaddr_in)
#include <arpa/inet.h> // inet_pton()
#include <unistd.h> // posix close(), read(), write()
#include <netdb.h> // for gethostbyname()
#include <iomanip> //setw
#include <set>

class ICMPTraceroute {
private:
    int sock;
    sockaddr_in dest{};
    std::string address;
    int maxHops;
    int timeoutMs;
    int payloadSize;
    int buffsize;
    int pid;
    bool verbose;

public:
    ICMPTraceroute(
        std::string addr,
        int maxHops = 30,
        int timeoutMs = 1000,
        int payloadSize = 32,
        int buffsize = 1024,
        bool verbose = false
    ) :
        address(addr),
        maxHops(maxHops),
        timeoutMs(timeoutMs),
        payloadSize(payloadSize),
        buffsize(buffsize),
        verbose(verbose)
    {
        this->pid = getpid() & 0xFFFF;
        displayInfo();
    }

    ~ICMPTraceroute() { close(this->sock); }
    void displayInfo() {
        if (this->verbose) {
            std::cout << "=== ICMP PING CONFIG ===" << std::endl;
            std::cout << "Target Address: " << this->address << std::endl;
            std::cout << "Buffer size: " << this->buffsize << " bytes" << std::endl;
            std::cout << "Max Hops: " << this->maxHops << std::endl;
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
        if (this->sock < 0) {
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
        if (inet_pton(AF_INET, this->address.c_str(), &this->dest.sin_addr) != 1) // Try as direct IP
        {
            // try to resolve as a hostname
            hostent* host = gethostbyname(this->address.c_str());
            if (!host) {
                std::cerr << "Error: Could not resolve host: " << this->address << std::endl;
                return 1;
            }
            this->dest.sin_addr = *reinterpret_cast<in_addr*>(host->h_addr); // represents the address (char* to in_addr)
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

        // fill payload with 0xAB
        if (payloadSize > 8) memset(buf + sizeof(hdr) + 8, 0xAB, payloadSize - 8);

        reinterpret_cast<icmphdr*>(buf)->checksum = checksum(buf, sizeof(hdr) + payloadSize); // calc checksum

        // Return total number of bytes written to buffer
        return sizeof(hdr) + payloadSize;
    }

    // Send echo request
    bool sendEcho(uint16_t seq, int ttl) {
        std::vector<uint8_t> buf(sizeof(icmphdr) + this->payloadSize); // Allocate buffer
        buildPacket(buf.data(), seq);

        // Set TTL for this hop (system call to configure socket)
        // IPPROTO_IP specifies that the option applies to the IP protocol layer
        // IP_TTL the specific option being set
        if (setsockopt(this->sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            perror("setsockopt TTL");
            return false;
        }

        ssize_t sent = sendto(
            this->sock,
            buf.data(), // data
            buf.size(),
            0, // Optional flags (MSG_DONTWAIT for non-blocking)
            (sockaddr*)&this->dest,
            sizeof(this->dest)
        );

        if (sent < 0) {
            if (this->verbose) perror("sendto");
            return false;
        }
        return true;
    }

    int receiveEcho(double& rtt_ms, std::string& hopAddr, std::chrono::_V2::steady_clock::time_point send_time, int seq) {
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
        if (rv == 0) return 1; // timeout
        if (rv < 0) return 2; // error

        // recive data and sender info
        ssize_t n = recvfrom(this->sock, buf.data(), buf.size(), 0, (sockaddr*)&from, &addrlen);
        if (n <= 0) return 2; // 0 -> no data, n < 0 -> error

        hopAddr = inet_ntoa(from.sin_addr); // address from server

        // calc RTT (convert microseconds → milliseconds)
        std::chrono::_V2::steady_clock::time_point recv_time = std::chrono::steady_clock::now();
        rtt_ms = std::chrono::duration<double, std::milli>(recv_time - send_time).count();

        // IP header length
        int ihl = reinterpret_cast<iphdr*>(buf.data())->ihl * 4; // get the the IP header structure and ihl ("Internet Header Length") * 4 (IP header is, in units of 32-bit words (4 bytes each) so it converts to bytes)
        // pointer to start of ICMP message
        icmphdr* icmp = reinterpret_cast<icmphdr*>(buf.data() + ihl); // buff pinter + IP legth

        // --- NEW CODE BELOW: Verify ICMP identifier and sequence ---
        uint16_t expected_id = htons(this->pid); // assuming you store your process ID or unique identifier
        uint16_t expected_seq = htons(seq); // assuming you track the sent seq number
        bool match = false;

        if (icmp->type == ICMP_ECHOREPLY) {
            // Direct Echo Reply (final destination)
            if (icmp->un.echo.id == expected_id && icmp->un.echo.sequence == expected_seq) {
                match = true;
            }
        } else if (icmp->type == ICMP_TIME_EXCEEDED) {
            // ICMP Time Exceeded contains the original IP header + 8 bytes of original payload
            iphdr* inner_ip = reinterpret_cast<iphdr*>(buf.data() + ihl + sizeof(icmphdr)); // inner IP header
            int inner_ihl = inner_ip->ihl * 4;
            icmphdr* inner_icmp = reinterpret_cast<icmphdr*>(reinterpret_cast<uint8_t*>(inner_ip) + inner_ihl);

            // Match inner ICMP ID and SEQ with what we sent
            if (inner_icmp->un.echo.id == expected_id && inner_icmp->un.echo.sequence == expected_seq) {
                match = true;
            }
        }

        // If the ICMP message does not belong to us, ignore and wait again
        if (!match) {
            return receiveEcho(rtt_ms, hopAddr, send_time, seq); // recursively wait for the correct one
        }
        // --- END OF NEW CODE ---

        if (icmp->type == ICMP_TIME_EXCEEDED) {
            return 3; // hop, but not destination
        } else if (icmp->type == ICMP_ECHOREPLY) {
            return 0; // destination reached
        }

        return 4; // unknown response
    }

public:
    int run() {
        createSocket();
        std::cout << "Tracing route to " << this->address << " (" << inet_ntoa(this->dest.sin_addr) << "), max " << this->maxHops << " hops\n";

        for (int ttl = 1; ttl <= this->maxHops; ++ttl) {
            std::cout << std::setw(2) << ttl << "  " << std::flush;

            struct ResultsProperties {
                std::string addr;
                double rtt;
                bool timeout;
            };

            ResultsProperties attemptsResult = {"", 0.0, false};
            ResultsProperties lastAttempt = {"", 0.0, false};
            bool destinationReached = false;

            for (int attempt = 1; attempt <= 3; ++attempt) {
                double rtt = 0.0;
                uint16_t seq = (ttl - 1) * 3 + attempt;
                std::string hopAddr;

                std::chrono::_V2::steady_clock::time_point send_time = std::chrono::steady_clock::now();
                if (!sendEcho(seq, ttl)) continue;

                int result = receiveEcho(rtt, hopAddr, send_time, seq);

                if (result == 1) {
                    attemptsResult = {"", 0.0, true};
                } else if (result == 2) {
                    attemptsResult = {"sockerr", 0.0, false};
                } else if (result == 3 || result == 0) {
                    attemptsResult = {hopAddr, rtt, false};
                    if (result == 0) destinationReached = true;
                } else {
                    attemptsResult = {"?", 0.0, false};
                }

                // print unique address
                if (attemptsResult.timeout){
                }else if (!attemptsResult.addr.empty() && attemptsResult.addr != lastAttempt.addr) {
                    in_addr addrStruct{};
                    inet_pton(AF_INET, attemptsResult.addr.c_str(), &addrStruct);
                    hostent* hopHost = gethostbyaddr(&addrStruct, sizeof(addrStruct), AF_INET);
                    std::string hopName = (hopHost && hopHost->h_name) ? hopHost->h_name : attemptsResult.addr;

                    std::cout << hopName << " (" << attemptsResult.addr << ")  ";
                    lastAttempt.addr = attemptsResult.addr;
                }

                // Print RTTs or timeout
                if (attemptsResult.timeout)
                    std::cout << std::setw(8) << "***" << std::flush;
                else if (attemptsResult.addr == "sockerr" || attemptsResult.addr == "?")
                    std::cout << std::setw(8) << attemptsResult.addr << std::flush;
                else {
                    std::ostringstream oss;
                    oss << std::fixed << std::setprecision(1) << attemptsResult.rtt << " ms";
                    std::cout << std::setw(8) << oss.str() << std::flush;
                }
            }

            std::cout << std::endl;

            if (destinationReached) {
                std::cout << "[Destination Reached]" << std::endl;
                break;
            }
        }
        return 1;
    }
};

int main(int argc, char* argv[]) {
    std::string address = "8.8.8.8";
    int maxHops = 30;
    int timeout = 1000;
    bool verbose = false;
    int payloadSize = 32;
    int buffsize = 1024;

    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " [address] [-v] [--maxhops <n>] [--timeout <ms>] [--payloadSize <bytes>] [--buffsize <bytes>]" << std::endl;
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--maxhops" && i + 1 < argc)
            maxHops = std::stoi(argv[++i]);
        else if (arg == "--timeout" && i + 1 < argc)
            timeout = std::stoi(argv[++i]);
        else if (arg == "--payloadSize" && i + 1 < argc)
            payloadSize = std::stoi(argv[++i]);
        else if (arg == "--buffsize" && i + 1 < argc)
            buffsize = std::stoi(argv[++i]);
        else if (arg == "-v")
            verbose = true;
        else if (arg[0] != '-')
            address = arg;
    }

    ICMPTraceroute tracer(address, maxHops, timeout, payloadSize, buffsize, verbose);
    return tracer.run();
}