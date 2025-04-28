#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <csignal> // Dùng signal() để bắt Ctrl+C
//#include <openssl/aes.h>      // Cho các hàm, cấu trúc AES
//#include <openssl/evp.h>      // Cho API mã hóa cấp cao (EVP_* functions)
//#include <openssl/rand.h>     // Để tạo số ngẫu nhiên (ví dụ tạo IV)
//#include <openssl/err.h>      // Để xử lý lỗi OpenSSL
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <cstdint>
#include <string>
#include <chrono>


#pragma comment(lib, "Ws2_32.lib")

using namespace std;

class info {
private:
    std::string id;
    std::string ad;
    std::string realm;
    std::string pub_key;
    std::string pri_key;

public:
    std::string getID() const;       
    std::string getAD() const;       
    std::string getRealm() const;  
    std::string getPublicKey() const; 
};



// Cấu trúc Service Ticket
struct ServiceTicket {
    std::string clientID;        // Thông tin định danh Client
    std::string flags;           // Các cờ (flags)
    std::string sessionKey;      // Khóa phiên giữa Client và Server V
    std::string clientAD;        // Thông tin định danh Client
    std::string realmc;

    struct TimeInfo {
        std::chrono::system_clock::time_point from;   // Thời gian bắt đầu hợp lệ
        std::chrono::system_clock::time_point till;   // Thời gian hết hạn
        std::chrono::system_clock::time_point rtime;  // Thời gian kiểm tra
    } timeInfo;
};


// Cấu trúc Bộ xác thực
struct AuthenticatorC {
    std::string clientID;
    std::string realmc;
    std::chrono::system_clock::time_point TS2;    // Timestamp khi Client gửi yêu cầu
    std::string subkey;    // Subkey bảo vệ phiên giao dịch
    uint32_t seqNum;       // Sequence number để tránh tấn công phát lại
};

// Hàm nhận và xử lý dữ liệu từ TGS
struct TGSData {
    std::string realmC;
    std::string idC;
    std::string ticketV;
    std::string kcV;       // Khóa phiên giữa Client và Server V
    struct TimeInfo {
        std::chrono::system_clock::time_point from;   // Thời gian bắt đầu hợp lệ
        std::chrono::system_clock::time_point till;   // Thời gian hết hạn
        std::chrono::system_clock::time_point rtime;  // Thời gian kiểm tra
    } timeInfo;
    std::string nonce2;    // Nonce gửi kèm
    std::string realmV;    // Realm của Server V
    std::string idV;       // ID của Server V

    TGSData(const std::string& rc, const std::string& id, const std::string& ticket,
        const std::string& kc, std::chrono::system_clock::time_point tf,
        std::chrono::system_clock::time_point tt, std::chrono::system_clock::time_point trt,
        const std::string& n, const std::string& rv, const std::string& iv)
        : realmC(rc), idC(id), ticketV(ticket), kcV(kc), timeInfo{ tf, tt, trt }, nonce2(n), realmV(rv), idV(iv) {}
};

//client
std::string aes_encrypt_cbc(const std::string& plaintext, const std::string& key, const std::string& iv);
std::string aes_decrypt_cbc(const std::string& cyphertext, const std::string& key, const std::string& iv);
void handleCtrlC(int sig);

//hash SHA1
uint32_t left_rotate(uint32_t value, unsigned int count);
string sha1(const string& input);

std::vector<std::string> splitString(const std::string& input, const std::string& delimiter);
std::chrono::system_clock::time_point parseTimestamp(const std::string& timestamp);


