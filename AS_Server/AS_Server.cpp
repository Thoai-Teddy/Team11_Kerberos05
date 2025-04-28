#include "../Utils/Utils.h"


int main() {
    WSADATA wsaData;
    SOCKET asSocket, clientSocket;
    sockaddr_in asAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[1024];

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    asSocket = socket(AF_INET, SOCK_STREAM, 0);
    asAddr.sin_family = AF_INET;
    asAddr.sin_addr.s_addr = INADDR_ANY;
    asAddr.sin_port = htons(8800);

    bind(asSocket, (sockaddr*)&asAddr, sizeof(asAddr));
    listen(asSocket, 5);

    cout << "AS Server listening on port 8800...\n";

    clientSocket = accept(asSocket, (sockaddr*)&clientAddr, &clientAddrLen);
    cout << "Client connected to AS.\n";

    // Nhận username
    memset(buffer, 0, sizeof(buffer));
    recv(clientSocket, buffer, sizeof(buffer), 0);
    cout << "Received username: " << buffer << "\n";

    // Gửi lại TGT (ở đây giả lập TGT là "TGT_for_[username]")
    string tgt = "TGT_for_" + string(buffer);
    send(clientSocket, tgt.c_str(), tgt.length(), 0);

    closesocket(clientSocket);
    closesocket(asSocket);
    WSACleanup();
    return 0;
}
