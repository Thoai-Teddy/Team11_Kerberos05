#include "../Utils/Utils.h"

SOCKET clientSocket; // Để đóng socket khi cần

// Hàm xử lý Ctrl+C
void handleCtrlC(int sig) {
    cout << "\nDisconnecting from server..." << endl;
    closesocket(clientSocket);
    WSACleanup();
    exit(0);
}

int main() {
    WSADATA wsaData;
    sockaddr_in serverAddr;
    char buffer[1024];

    // Bắt Ctrl+C
    signal(SIGINT, handleCtrlC);

    // Khởi tạo Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed." << endl;
        return 1;
    }

    // Tạo socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "Socket creation failed." << endl;
        WSACleanup();
        return 1;
    }

    // Cấu hình server
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8800); // Kết nối tới cổng 8800 của AS Server
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr); // Hoặc đổi IP khác nếu cần

    // Kết nối server
    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Connection to server failed." << endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    cout << "Connected to AS Server." << endl;

    // Gửi username tới AS Server
    cout << "Enter username: ";
    cin.getline(buffer, sizeof(buffer));
    send(clientSocket, buffer, strlen(buffer), 0);

    // Nhận TGT từ AS Server
    memset(buffer, 0, sizeof(buffer)); // Clear buffer
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived > 0) {
        cout << "Received TGT: " << buffer << endl;
    }

    // Đóng kết nối với AS Server
    closesocket(clientSocket);

    // Kết nối tới TGS Server
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    serverAddr.sin_port = htons(8801); // Kết nối tới cổng 8801 của TGS Server

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Connection to TGS failed." << endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    // Gửi TGT tới TGS Server
    send(clientSocket, buffer, strlen(buffer), 0);

    // Nhận Service Ticket từ TGS Server
    memset(buffer, 0, sizeof(buffer)); // Clear buffer
    bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived > 0) {
        cout << "Received Service Ticket: " << buffer << endl;
    }

    // Đóng kết nối với TGS Server
    closesocket(clientSocket);

    // Kết nối tới Service Server
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    serverAddr.sin_port = htons(8802); // Kết nối tới cổng 8802 của Service Server

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Connection to Service Server failed." << endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    // Gửi Service Ticket tới Service Server
    send(clientSocket, buffer, strlen(buffer), 0);

    // Nhận dữ liệu từ Service Server
    memset(buffer, 0, sizeof(buffer)); // Clear buffer
    bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived > 0) {
        cout << "Received Service Data: " << buffer << endl;
    }

    // Đóng kết nối với Service Server
    closesocket(clientSocket);
    WSACleanup();

    return 0;
}
