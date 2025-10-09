#include <cstring> //strings
#include <iostream> //output (cout, cin)
#include <netinet/in.h> //socket struct and utils (sockaddr_in)
#include <sys/socket.h> //create socket
#include <unistd.h> //posix close(), read(), write()

using namespace std;

int main()
{
    //* define server address

    // creating socket
    // AF_INET: protocolo IPv4
    // SOCK_STREAM: TCP
    // 0: use standard protocol (TCP)
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    // specifying the address where server will listen
    // sin_family = AF_INET: address type IPv4.
    // sin_port = htons(8080): define the port 8080.
    // sin_addr.s_addr = INADDR_ANY: accept from any interface.
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // associet socket to the port
    bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

    // listening to the assigned socket
    listen(serverSocket, 5);

    // accepting connection request
    int clientSocket
        = accept(serverSocket, nullptr, nullptr);

    // recieving data
    char buffer[1024] = { 0 };
    recv(clientSocket, buffer, sizeof(buffer), 0);
    cout << "Message from client: " << buffer << endl;

    // closing the socket.
    close(serverSocket);

    return 0;
}