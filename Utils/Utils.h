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
#include <ctime>
#include <random>
#include <bitset>
#include <soci/soci.h>
#include <soci/odbc/soci-odbc.h>

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
    info(const std::string& id, const std::string& realm, const std::string ad)
        : id(id), realm(realm), ad(ad), pub_key(""), pri_key("") {};
    // Constructor để khởi tạo các giá trị
    info(const std::string& id, const std::string& ad, const std::string& realm,
        const std::string& pub_key, const std::string& pri_key)
        : id(id), ad(ad), realm(realm), pub_key(pub_key), pri_key(pri_key) {}

    std::string getID() const;       
    std::string getAD() const;       
    std::string getRealm() const;  
    std::string getPublicKey() const; 
    void setPrivateKey(std::string privateKey);
    void setID(const std::string& newID) { id = newID; }
    void setAD(const std::string& newAD) { ad = newAD; }
    void setRealm(const std::string& newRealm) { realm = newRealm; }
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
//Hàm lưu thông tin Ticket sau khi giải mã:
ServiceTicket parseServiceTicket(const string& decryptedText);
//Hàm in ServiceTicket:
void printServiceTicket(const ServiceTicket& ticket);


// Cấu trúc Bộ xác thực
struct AuthenticatorC {
    std::string clientID;
    std::string realmc;
    std::chrono::system_clock::time_point TS2;    // Timestamp khi Client gửi yêu cầu
    std::string subkey;    // Subkey bảo vệ phiên giao dịch
    uint32_t seqNum;       // Sequence number để tránh tấn công phát lại
};

//hàm lưu giá trị vào AuthenticatorC sau khi giải mã:
AuthenticatorC parseAuthenticator(const string& decryptedText);


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

// Cấu trúc Dữ liệu mã hóa Server gửi cho Client
struct ServiceServerData {
    std::string clientID;        // Thông tin định danh Client
    std::string encryptedData;   // Dữ liệu đã mã hóa (E(Kc,v [TS2 || Subkey || Seq #]))
    std::chrono::system_clock::time_point TS2;    // Timestamp khi Server gửi dữ liệu
    std::string subkey;          // Subkey bảo vệ phiên giao dịch
    uint32_t seqNum;             // Sequence number để tránh tấn công phát lại
    std::string kcV;             // Khóa phiên giữa Client và Server V

    // Constructor mặc định
    ServiceServerData() : seqNum(0), TS2(std::chrono::system_clock::now()) {}

    // Constructor để khởi tạo dữ liệu mã hóa
    ServiceServerData(const std::string& client, const std::string& encData,
        std::chrono::system_clock::time_point ts, const std::string& subk,
        uint32_t seq, const std::string& kc)
        : clientID(client), encryptedData(encData), TS2(ts), subkey(subk), seqNum(seq), kcV(kc) {}
};
ServiceTicket createServiceTicket(const std::string& clientID, const std::string& flags, const std::string& sessionKey, const std::string& clientAD, 
    const std::string& realmc, const std::chrono::system_clock::time_point& from, const std::chrono::system_clock::time_point& till,
    const std::chrono::system_clock::time_point& rtime);

std::chrono::system_clock::time_point createTS2();
std::string timeToString(std::chrono::system_clock::time_point timePoint);

std::string createSubkey(const std::string& key, const std::string& data);



// Hàm hỗ trợ: chuyển timestamp dạng chuỗi sang std::chrono::system_clock::time_point
chrono::system_clock::time_point millisecTimestampToTimePoint(const string& timestampStr);
chrono::system_clock::time_point secondTimestampToTimePoint(const string& ts_str);

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
std::vector<unsigned char> hexStringToVector(const std::string& hexStr);
std::vector<std::string> splitString(const std::string& input, const std::string& delimiter);
std::chrono::system_clock::time_point parseTimestamp(const std::string& timestamp);
std::string trim(const std::string& s);

//Step 6: Service Server reply to Client:
// Hàm tách chuỗi bằng dấu '|' và gán vào các biến
void splitAndAssign(const std::string& input, std::string& a, std::string& b, std::string& c);

//hàm tạo thông tin Service Ticket để test:
uint64_t getCurrentTimestamp();
std::string buildServiceTicketPlaintext(const std::string& flag,
    const std::string& sessionKey,
    const std::string& realmc,
    const std::string& clientID,
    const std::string& clientAD,
    uint64_t from, uint64_t till, uint64_t rtime);




// Cấu trúc  Ticket
struct Ticket {
    std::string clientID;        // Thông tin định danh Client
    std::string flags;           // Các cờ (flags)
    std::string sessionKey;      // Khóa phiên giữa Client và Server V
    std::string clientAD;        // Thông tin định danh Client
    std::string realmc;
    std::string times_from;
    std::string times_till;
    std::string times_rtime;
};




std::string generate_nonce(int length);

std::string get_current_time_formatted();

std::string build_times(int ticket_lifetime, int renew_lifetime);

void send_message(SOCKET sock, const std::string& message);

std::string receive_message(SOCKET sock);

// Hàm tạo chuỗi 16 ký tự ngẫu nhiên (dùng để tạo key và iv)
std::string generateRandomString(size_t length = 16);

//hàm tách iv khỏi message:
std::string extractAfterFirstDoublePipe(std::string& input);
std::string extractAfterSecondDoublePipe(std::string& input);

//check Time
std::string create_ticket_time(int ticket_lifetime, int renew_lifetime);
std::string check_ticket_time(std::string from, std::string till, std::string rtime);

//hàm tạo option bước 5
uint32_t createAPOptions(bool useSessionKey, bool mutualRequired);
std::string apOptionsToBitString(uint32_t options); //trả về chuỗi nhị phân
bool checkAPOptionsFromBitString(const std::string& bitStr); //check option in step 5