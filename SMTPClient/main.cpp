/*
 * Setting args
 * Usage: ./smtp_client <port> [address] [-v] [--buffsize <bytes>]
 * Exemple: ./smtp_client 8080 127.0.0.1 -v --buffsize 1024
 */

#include <cstring> // strings
#include <iostream> // output (cout, cin)
#include <netinet/in.h> // socket struct and utils (sockaddr_in)
#include <sys/socket.h> // create socket
#include <unistd.h> // posix close(), read(), write()
#include <arpa/inet.h> // inet_pton()

class SMTPSocketClient
{
private:
    int port;
    std::string address;
    bool verbose;
    int buffsize;

    // socket
    int clientSocket;
    char *buffer;
    sockaddr_in serverAddress;
public:
    SMTPSocketClient(
        int port,
        std::string address = "127.0.0.1",
        bool verbose = false,
        int buffsize = 1024
    ) :
        port(port),
        address(address),
        verbose(verbose),
        buffsize(buffsize)
    {
        displayInfo();
    }


    void displayInfo() {
        if (this->verbose) {
            std::cout << "=== UDP SERVER CONFIG ===" << std::endl;
            std::cout << "Server Address: " << address << std::endl;
            std::cout << "Server Port: " << port << std::endl;
            std::cout << "Buffer size: " << buffsize << " bytes" << std::endl;
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
        return 0;
    }

    ~SMTPSocketClient(){
        cleanup();
    };

    void cleanup(){
        close(this->clientSocket);
        delete[] this->buffer;
        this->buffer = nullptr;
    }
    int run(){

    }
};


int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <port> [address] [-v] [--buffsize <bytes>]" << std::endl;
        return 1;
    }

    //* Required: port
    int port = std::stoi(argv[1]);

    //* Optional args
    std::string address = "0.0.0.0"; // all interfaces by default
    bool verbose = false;
    int buffsize = 1024; // default buffer size

    //* Parse remaining args
    for (int i = 2; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "-v")
            verbose = true;
        else if (arg == "--buffsize" && i + 1 < argc)
            buffsize = std::stoi(argv[++i]);
        else if (address == "127.0.0.1" && arg[0] != '-')
            address = arg;
    }

    SMTPSocketClient client( port, address, verbose, buffsize);

    if (client.createSocket() != 0) return 1;

    return client.run();
}