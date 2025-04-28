#pragma once

#define CRT_SECURE_NO_WARNINGS

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

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

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

//Step 6: Service Server reply to Client:

