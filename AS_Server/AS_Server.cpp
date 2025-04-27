#include <winsock2.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdint>
#pragma comment(lib, "Ws2_32.lib")

using namespace std;

// Hàm dịch bit trái
uint32_t left_rotate(uint32_t value, unsigned int count) {
    return (value << count) | (value >> (32 - count));
}

// Hàm hash SHA-1
string sha1(const string& input) {
    // Khởi tạo các hằng số
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // Tiền xử lý (Pre-processing)
    vector<uint8_t> data(input.begin(), input.end());
    uint64_t original_bit_len = data.size() * 8;

    // Thêm bit '1'
    data.push_back(0x80);

    // Thêm các bit '0' để độ dài chia hết cho 512 - 64 = 448
    while ((data.size() * 8) % 512 != 448) {
        data.push_back(0x00);
    }

    // Thêm độ dài ban đầu (big-endian)
    for (int i = 7; i >= 0; --i) {
        data.push_back((original_bit_len >> (i * 8)) & 0xFF);
    }

    // Xử lý theo từng khối 512-bit
    for (size_t chunk = 0; chunk < data.size(); chunk += 64) {
        uint32_t w[80];
        // Chia 512 bits thành 16 từ 32 bits
        for (int i = 0; i < 16; ++i) {
            w[i] = (data[chunk + i * 4 + 0] << 24) |
                (data[chunk + i * 4 + 1] << 16) |
                (data[chunk + i * 4 + 2] << 8) |
                (data[chunk + i * 4 + 3]);
        }
        // Mở rộng thành 80 từ
        for (int i = 16; i < 80; ++i) {
            w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF;
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    stringstream ss;
    ss << hex << setfill('0');
    ss << setw(8) << h0;
    ss << setw(8) << h1;
    ss << setw(8) << h2;
    ss << setw(8) << h3;
    ss << setw(8) << h4;
    return ss.str();
}




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
