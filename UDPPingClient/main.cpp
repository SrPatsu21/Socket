#include <cstring> //strings
#include <iostream> //output (cout, cin)
#include <netinet/in.h> //socket struct and utils (sockaddr_in)
#include <sys/socket.h> //create socket
#include <unistd.h> //posix close(), read(), write()

int main() {

    //* Create a UDP socket
    // AF_INET → IPv4
    // SOCK_DGRAM → UDP protocol (unlike SOCK_STREAM for TCP)
    // 0 → choose default protocol for UDP
    int clientSocket = socket(AF_INET, SOCK_DGRAM, 0);

    // verify if socket was created
    if (clientSocket < 0) {
        throw std::runtime_error("Error: failed to create socket.");
        return 1;
    }

    //* Define the server address we want to send to
    sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress)); // Clear structure

    serverAddress.sin_family = AF_INET; // IPv4
    serverAddress.sin_port = htons(8080); // Host to Network Short (host byte order to network byte order)
    serverAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 (localhost)

    std::cout << "UDP client started. Type messages to send to the server." << std::endl;
    std::cout << "Type 'exit' to quit.\n" << std::endl;

    // Step 3: Loop to send messages and receive responses
    while (true) {
        std::string message;
        std::cout << "Enter message: ";
        getline(std::cin, message);

        // Exit condition
        if (message == "exit") {
            std::cout << "Exiting client..." << std::endl;
            break;
        }

        // Step 4: Send message to the server
        ssize_t bytesSent = sendto(
            clientSocket,
            message.c_str(),
            message.size(),
            0,
            (struct sockaddr*)&serverAddress,
            sizeof(serverAddress)
        );

        if (bytesSent < 0) {
            std::cerr << "Error: failed to send message." << std::endl;
            continue;
        }

        // Step 5: Wait for server response (optional)
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));

        socklen_t serverLen = sizeof(serverAddress);
        ssize_t bytesReceived = recvfrom(
            clientSocket,
            buffer,
            sizeof(buffer) - 1, // Reserve space for '\0'
            0,
            (struct sockaddr*)&serverAddress,
            &serverLen
        );

        if (bytesReceived < 0) {
            std::cerr << "Error: no response from server." << std::endl;
            continue;
        }

        buffer[bytesReceived] = '\0';
        std::cout << "Server reply: " << buffer << std::endl;
    }

    //* Close the socket
    close(clientSocket);
    return 0;
}