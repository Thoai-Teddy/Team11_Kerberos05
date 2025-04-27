#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <csignal> // Dùng signal() để bắt Ctrl+C
#include <openssl/aes.h>      // Cho các hàm, cấu trúc AES
#include <openssl/evp.h>      // Cho API mã hóa cấp cao (EVP_* functions)
#include <openssl/rand.h>     // Để tạo số ngẫu nhiên (ví dụ tạo IV)
#include <openssl/err.h>      // Để xử lý lỗi OpenSSL
#include <vector>
#include <stdexcept>
#pragma comment(lib, "Ws2_32.lib")

using namespace std;

SOCKET clientSocket; // Để đóng socket khi cần

// Hàm AES CBC Encrypt
std::vector<unsigned char> aes_encrypt_cbc(const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    std::vector<unsigned char> ciphertext(plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len); // Resize lại đúng kích thước thực
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

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
