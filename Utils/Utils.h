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


#pragma comment(lib, "Ws2_32.lib")

using namespace std;

//client
//std::vector<unsigned char> aes_encrypt_cbc(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, const unsigned char* iv);
void handleCtrlC(int sig);

//hash SHA1
uint32_t left_rotate(uint32_t value, unsigned int count);
string sha1(const string& input);


