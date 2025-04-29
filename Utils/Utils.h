#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <csignal> // Dùng signal() để bắt Ctrl+C
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
    info(const std::string& id, const std::string& realm)
        : id(id), realm(realm), ad(""), pub_key(""), pri_key("") {};
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


void handleCtrlC(int sig);
std::vector<std::string> splitString(const std::string& input, const std::string& delimiter);
std::chrono::system_clock::time_point parseTimestamp(const std::string& timestamp);

//hash SHA1
uint32_t left_rotate(uint32_t value, unsigned int count);
string sha1(const string& input);

// Hàm chuyển byte thành chuỗi hexadecimal
string bytesToHex(const vector<unsigned char>& bytes);

//AES-CBC:
unsigned int bytesToWord(const unsigned char* bytes);
void wordToBytes(unsigned int word, unsigned char* bytes);
void SubBytes(unsigned char* state);
void ShiftRows(unsigned char* state);
unsigned char GF(unsigned char x);
void MixColumns(unsigned char* state);
void AddRoundKey(unsigned char* state, const unsigned char* roundKey);
void KeyExpansion(const unsigned char* key, unsigned char* roundKeys);
void aes_encrypt_block(unsigned char* block, const unsigned char* key);
void xor_blocks(unsigned char* dst, const unsigned char* src);
void padding(vector<unsigned char>& data);
vector<unsigned char> aes_cbc_encrypt(const vector<unsigned char>& plaintext, const vector<unsigned char>& key, const vector<unsigned char>& iv);
void InvSubBytes(unsigned char* state);
void InvShiftRows(unsigned char* state);
void InvMixColumns(unsigned char* state);
void unpadding(vector<unsigned char>& data);
void aes_decrypt_block(unsigned char* block, const unsigned char* key);
vector<unsigned char> aes_cbc_decrypt(const vector<unsigned char>& ciphertext, const vector<unsigned char>& key, const vector<unsigned char>& iv);

vector<unsigned char> padString(const string& input);
string unpadString(const vector<unsigned char>& input);
string unpadString2(const vector<unsigned char>& input);
std::vector<unsigned char> hexStringToVector(const std::string& hexStr);
//Step 6: Service Server reply to Client:

