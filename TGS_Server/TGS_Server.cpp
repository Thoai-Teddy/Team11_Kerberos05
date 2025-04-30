#include "../Utils/Utils.h"

int main() {
    WSADATA wsaData;
    SOCKET tgsSocket, clientSocket;
    sockaddr_in tgsAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[1024];

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    tgsSocket = socket(AF_INET, SOCK_STREAM, 0);
    tgsAddr.sin_family = AF_INET;
    tgsAddr.sin_addr.s_addr = INADDR_ANY;
    tgsAddr.sin_port = htons(8801);

    bind(tgsSocket, (sockaddr*)&tgsAddr, sizeof(tgsAddr));
    listen(tgsSocket, 5);

    cout << "TGS Server listening on port 8801...\n";

    clientSocket = accept(tgsSocket, (sockaddr*)&clientAddr, &clientAddrLen);
    cout << "Client connected to TGS.\n";

    // Nhận TGT
    memset(buffer, 0, sizeof(buffer));
    recv(clientSocket, buffer, sizeof(buffer), 0);
    cout << "Received TGT: " << buffer << "\n";

    // Gửi Service Ticket
    string serviceTicket = "ServiceTicket_for_" + string(buffer);
    send(clientSocket, serviceTicket.c_str(), serviceTicket.length(), 0);

    closesocket(clientSocket);
    closesocket(tgsSocket);
    WSACleanup();
    return 0;
}
