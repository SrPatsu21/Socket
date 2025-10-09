#include <cstring> //strings
#include <iostream> //output (cout, cin)
#include <netinet/in.h> //socket struct and utils (sockaddr_in)
#include <sys/socket.h> //create socket
#include <unistd.h> //posix close(), read(), write()

int main() {

    //* Create the socket
    // AF_INET  → IPv4 address family
    // SOCK_DGRAM → UDP protocol (unlike SOCK_STREAM for TCP)
    // 0 → choose default protocol for UDP
    int serverSocket = socket(AF_INET, SOCK_DGRAM, 0);

    // verify if socket was created
    if (serverSocket < 0) {
        throw std::runtime_error("Error: failed to create socket.");
    }

    //* Configure the server address
    sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress)); // Clear structure memory

    serverAddress.sin_family = AF_INET; // IPv4
    serverAddress.sin_port = htons(8080); // Host to Network Short (host byte order to network byte order)
    serverAddress.sin_addr.s_addr = INADDR_ANY; // Listen on any network interface

    //* Bind the socket to the chosen port
    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Error: binding failed." << std::endl;
        close(serverSocket);
        return 1;
    }

    std::cout << "UDP server is listening on port 8080..." << std::endl;

    //* wait messages from clients
    char buffer[1024]; // Buffer for incoming data
    sockaddr_in clientAddress; // To store client address
    socklen_t clientAddressLen = sizeof(clientAddress);

    while (true) {
        memset(buffer, 0, sizeof(buffer)); // Clear buffer before receiving new data

        // recvfrom() waits for a UDP packet and fills buffer + client info
        ssize_t bytesReceived = recvfrom(
            serverSocket,
            buffer,
            sizeof(buffer) - 1,  // Leave space for null terminator
            0,
            (struct sockaddr*)&clientAddress,
            &clientAddressLen
        );

        if (bytesReceived < 0) {
            std::cerr << "Error receiving data." << std::endl;
            continue;
        }

        buffer[bytesReceived] = '\0'; // Ensure null-terminated string
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

    // Step 6: Close the socket (this line is never reached in this loop)
    close(serverSocket);

    return 0;
}