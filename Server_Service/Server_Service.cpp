#include "../Utils/Utils.h"


int main() {
    WSADATA wsaData;
    SOCKET serviceSocket, clientSocket;
    sockaddr_in serviceAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[1024];

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    serviceSocket = socket(AF_INET, SOCK_STREAM, 0);
    serviceAddr.sin_family = AF_INET;
    serviceAddr.sin_addr.s_addr = INADDR_ANY;
    serviceAddr.sin_port = htons(8802);

    bind(serviceSocket, (sockaddr*)&serviceAddr, sizeof(serviceAddr));
    listen(serviceSocket, 5);

    cout << "Service Server listening on port 8802...\n";

    clientSocket = accept(serviceSocket, (sockaddr*)&clientAddr, &clientAddrLen);
    cout << "Client connected to Service Server.\n";

    // Nhận Service Ticket
    memset(buffer, 0, sizeof(buffer));
    recv(clientSocket, buffer, sizeof(buffer), 0);
    cout << "Received Service Ticket: " << buffer << "\n";

    // Gửi dịch vụ thực tế
    string serviceData = "Welcome! Here is your service data.";
    send(clientSocket, serviceData.c_str(), serviceData.length(), 0);

    closesocket(clientSocket);
    closesocket(serviceSocket);
    WSACleanup();
    return 0;
}
