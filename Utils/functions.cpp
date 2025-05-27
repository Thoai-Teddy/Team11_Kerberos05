#include "./Utils.h"

//Option step 5
enum APOptions {
    RESERVED = 1u << 31,       // Bit 0 (MSB)
    USE_SESSION_KEY = 1u << 30,// Bit 1
    MUTUAL_REQUIRED = 1u << 29 // Bit 2
};

const int BLOCK_SIZE = 16;
const int Nk = 4;          // 8 words * 4 bytes = 32 bytes = 256 bits
const int Nr = 10;         // 14 rounds cho AES-256

// AES S-box
unsigned char sbox[256] = {
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Rcon - Round constants
unsigned char Rcon[11] = {
    0x00,
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
};

unsigned char rsbox[256] = {
  0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,
  0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
  0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,
  0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
  0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,
  0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
  0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,
  0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
  0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,
  0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
  0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,
  0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
  0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,
  0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
  0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,
  0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
  0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,
  0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
  0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,
  0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
  0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,
  0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
  0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,
  0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
  0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,
  0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
  0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,
  0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
  0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,
  0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
  0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,
  0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};


//class info
std::string info::getID() const {
    return id;
};

std::string info::getAD() const {
    return ad;
};

std::string info::getRealm() const {
    return realm;
};

std::string info::getPublicKey() const {
    return pub_key;
};

std::string info::getPrivateKey() const {
    return pri_key;
};


void info::setPrivateKey(std::string privateKey) {
    this->pri_key = privateKey;
}

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

// Hàm chuyển byte thành chuỗi hexadecimal
string bytesToHex(const vector<unsigned char>& bytes) {
    stringstream ss;
    for (unsigned char byte : bytes) {
        ss << hex << setw(2) << setfill('0') << (int)byte;
    }
    return ss.str();
}

std::vector<unsigned char> hexStringToVector(const std::string& hexStr) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::string byteString = hexStr.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Hàm chuyển đổi chuỗi sang mảng bytes
vector<unsigned char> stringToBytes(const string& str) {
    return vector<unsigned char>(str.begin(), str.end());
}

// Hàm chuyển đổi vector bytes thành string
string bytesToString(const vector<unsigned char>& bytes) {
    return string(bytes.begin(), bytes.end());
}

//=========================AES-CBC=========================
// Gộp 4 bytes thành 1 word
unsigned int bytesToWord(const unsigned char* bytes) {
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}
// Tách 1 word thành 4 bytes
void wordToBytes(unsigned int word, unsigned char* bytes) {
    bytes[0] = (word >> 24) & 0xFF;
    bytes[1] = (word >> 16) & 0xFF;
    bytes[2] = (word >> 8) & 0xFF;
    bytes[3] = word & 0xFF;
}

// SubBytes
void SubBytes(unsigned char* state) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] = sbox[state[i]];
    }
}
// ShiftRows
void ShiftRows(unsigned char* state) {
    unsigned char temp[BLOCK_SIZE];

    // Row 0
    temp[0] = state[0];
    temp[4] = state[4];
    temp[8] = state[8];
    temp[12] = state[12];

    // Row 1
    temp[1] = state[5];
    temp[5] = state[9];
    temp[9] = state[13];
    temp[13] = state[1];

    // Row 2
    temp[2] = state[10];
    temp[6] = state[14];
    temp[10] = state[2];
    temp[14] = state[6];

    // Row 3
    temp[3] = state[15];
    temp[7] = state[3];
    temp[11] = state[7];
    temp[15] = state[11];

    memcpy(state, temp, BLOCK_SIZE);
}
// Nhân trong trường GF(2^8)
unsigned char GF(unsigned char x) {
    return (x << 1) ^ ((x >> 7) * 0x1b);
}
// MixColumns
void MixColumns(unsigned char* state) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        unsigned char a = state[i];
        unsigned char b = state[i + 1];
        unsigned char c1 = state[i + 2];
        unsigned char d = state[i + 3];

        unsigned char e = a ^ b ^ c1 ^ d;
        unsigned char xa = a;
        unsigned char xb = b;
        unsigned char xc = c1;
        unsigned char xd = d;

        state[i] ^= e ^ GF(a ^ b);
        state[i + 1] ^= e ^ GF(b ^ c1);
        state[i + 2] ^= e ^ GF(c1 ^ d);
        state[i + 3] ^= e ^ GF(d ^ a);
    }
}
// AddRoundKey
void AddRoundKey(unsigned char* state, const unsigned char* roundKey) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] ^= roundKey[i];
    }
}
// Key expansion
void KeyExpansion(const unsigned char* key, unsigned char* roundKeys) {
    unsigned int temp;
    unsigned int* w = (unsigned int*)roundKeys;

    for (int i = 0; i < Nk; i++) {
        w[i] = bytesToWord(&key[4 * i]);
    }

    for (int i = Nk; i < 4 * (Nr + 1); i++) {
        temp = w[i - 1];
        if (i % Nk == 0) {
            // Rotate word
            temp = (temp << 8) | (temp >> 24);
            // Sub word
            unsigned char t[4];
            wordToBytes(temp, t);
            t[0] = sbox[t[0]];
            t[1] = sbox[t[1]];
            t[2] = sbox[t[2]];
            t[3] = sbox[t[3]];
            temp = bytesToWord(t);
            // XOR with Rcon
            temp ^= (Rcon[i / Nk] << 24);
        }
        else if (Nk > 6 && i % Nk == 4) {
            // Thêm SubWord nếu AES-256
            unsigned char t[4];
            wordToBytes(temp, t);
            t[0] = sbox[t[0]];
            t[1] = sbox[t[1]];
            t[2] = sbox[t[2]];
            t[3] = sbox[t[3]];
            temp = bytesToWord(t);
        }
        w[i] = w[i - Nk] ^ temp;
    }
}
void aes_encrypt_block(unsigned char* block, const unsigned char* key) {
    unsigned char roundKeys[240];
    KeyExpansion(key, roundKeys);

    AddRoundKey(block, roundKeys);

    for (int round = 1; round < Nr; round++) {
        SubBytes(block);
        ShiftRows(block);
        MixColumns(block);
        AddRoundKey(block, roundKeys + round * BLOCK_SIZE);
    }

    // Round cuối không có MixColumns
    SubBytes(block);
    ShiftRows(block);
    AddRoundKey(block, roundKeys + Nr * BLOCK_SIZE);
}


void xor_blocks(unsigned char* dst, const unsigned char* src) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        dst[i] ^= src[i];
    }
}
void padding(vector<unsigned char>& data) {
    int pad_len = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
    for (int i = 0; i < pad_len; i++) {
        data.push_back((unsigned char)pad_len);
    }
}

// CBC Encrypt
vector<unsigned char> aes_cbc_encrypt(
    const vector<unsigned char>& plaintext,
    const vector<unsigned char>& key,
    const vector<unsigned char>& iv
) {
    vector<unsigned char> data = plaintext;
    padding(data);

    vector<unsigned char> ciphertext;
    unsigned char prev_block[BLOCK_SIZE];
    memcpy(prev_block, iv.data(), BLOCK_SIZE);

    for (size_t i = 0; i < data.size(); i += BLOCK_SIZE) {
        unsigned char block[BLOCK_SIZE];
        memcpy(block, &data[i], BLOCK_SIZE);

        xor_blocks(block, prev_block);
        aes_encrypt_block(block, key.data());

        ciphertext.insert(ciphertext.end(), block, block + BLOCK_SIZE);
        memcpy(prev_block, block, BLOCK_SIZE);
    }

    return ciphertext;
}
void InvSubBytes(unsigned char* state) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] = rsbox[state[i]];
    }
}
void InvShiftRows(unsigned char* state) {
    unsigned char temp[BLOCK_SIZE];

    temp[0] = state[0];
    temp[4] = state[4];
    temp[8] = state[8];
    temp[12] = state[12];

    temp[1] = state[13];
    temp[5] = state[1];
    temp[9] = state[5];
    temp[13] = state[9];

    temp[2] = state[10];
    temp[6] = state[14];
    temp[10] = state[2];
    temp[14] = state[6];

    temp[3] = state[7];
    temp[7] = state[11];
    temp[11] = state[15];
    temp[15] = state[3];

    memcpy(state, temp, BLOCK_SIZE);
}
void InvMixColumns(unsigned char* state) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        unsigned char a = state[i];
        unsigned char b = state[i + 1];
        unsigned char c1 = state[i + 2];
        unsigned char d = state[i + 3];

        unsigned char a2 = GF(a);
        unsigned char b2 = GF(b);
        unsigned char c2 = GF(c1);
        unsigned char d2 = GF(d);

        unsigned char a4 = GF(a2);
        unsigned char b4 = GF(b2);
        unsigned char c4 = GF(c2);
        unsigned char d4 = GF(d2);

        unsigned char a8 = GF(a4);
        unsigned char b8 = GF(b4);
        unsigned char c8 = GF(c4);
        unsigned char d8 = GF(d4);

        unsigned char a9 = a8 ^ a;
        unsigned char b9 = b8 ^ b;
        unsigned char c9 = c8 ^ c1;
        unsigned char d9 = d8 ^ d;

        unsigned char aB = a9 ^ a2;
        unsigned char bB = b9 ^ b2;
        unsigned char cB = c9 ^ c2;
        unsigned char dB = d9 ^ d2;

        unsigned char aD = a9 ^ a4;
        unsigned char bD = b9 ^ b4;
        unsigned char cD = c9 ^ c4;
        unsigned char dD = d9 ^ d4;

        unsigned char aE = a8 ^ a4 ^ a2;
        unsigned char bE = b8 ^ b4 ^ b2;
        unsigned char cE = c8 ^ c4 ^ c2;
        unsigned char dE = d8 ^ d4 ^ d2;

        state[i] = aE ^ bB ^ cD ^ d9;
        state[i + 1] = a9 ^ bE ^ cB ^ dD;
        state[i + 2] = aD ^ b9 ^ cE ^ dB;
        state[i + 3] = aB ^ bD ^ c9 ^ dE;
    }
}
void unpadding(vector<unsigned char>& data) {
    int pad_len = data.back();
    data.resize(data.size() - pad_len);
}
void aes_decrypt_block(unsigned char* block, const unsigned char* key) {
    unsigned char roundKeys[240]; // AES-256
    KeyExpansion(key, roundKeys);

    unsigned char state[BLOCK_SIZE];
    memcpy(state, block, BLOCK_SIZE);

    AddRoundKey(state, roundKeys + Nr * BLOCK_SIZE);

    for (int round = Nr - 1; round >= 1; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * BLOCK_SIZE);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);

    memcpy(block, state, BLOCK_SIZE);
}

vector<unsigned char> aes_cbc_decrypt(
    const vector<unsigned char>& ciphertext,
    const vector<unsigned char>& key,
    const vector<unsigned char>& iv
) {
    vector<unsigned char> plaintext;
    unsigned char prev_block[BLOCK_SIZE];
    memcpy(prev_block, iv.data(), BLOCK_SIZE);

    for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE) {
        unsigned char block[BLOCK_SIZE];
        memcpy(block, &ciphertext[i], BLOCK_SIZE);

        unsigned char temp[BLOCK_SIZE];
        memcpy(temp, block, BLOCK_SIZE);

        aes_decrypt_block(block, key.data());
        xor_blocks(block, prev_block);

        plaintext.insert(plaintext.end(), block, block + BLOCK_SIZE);
        memcpy(prev_block, temp, BLOCK_SIZE);
    }

    unpadding(plaintext);

    std::string plaintext_str(plaintext.begin(), plaintext.end());

    return plaintext;
}

vector<unsigned char> padString(const string& input) {
    vector<unsigned char> output(input.begin(), input.end());
    size_t paddingLength = 16 - (output.size() % 16);
    for (size_t i = 0; i < paddingLength; ++i) {
        output.push_back(paddingLength);
    }
    return output;
}

string unpadString(const vector<unsigned char>& input) {
    if (input.empty()) return "";
    unsigned char paddingLength = input.back();
    if (paddingLength > 16) return ""; // lỗi
    return string(input.begin(), input.end() - paddingLength);
}

string unpadString2(const vector<unsigned char>& input) {
    return string(input.begin(), input.end());
}



// Hàm tách chuỗi dựa trên dấu phân cách
std::vector<std::string> splitString(const std::string& input, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0, end = 0;
    while ((end = input.find(delimiter, start)) != std::string::npos) {
        tokens.push_back(input.substr(start, end - start));
        start = end + delimiter.length();
    }
    tokens.push_back(input.substr(start));
    return tokens;
}

std::chrono::system_clock::time_point parseTimestamp(const std::string& timestamp) {
    std::tm tm = {};
    std::istringstream ss(timestamp);

    // đọc chuỗi theo định dạng ngày giờ
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S"); // định dạng tương ứng với chuỗi nhập vào
    if (ss.fail()) {
        throw std::invalid_argument("invalid timestamp format");
    }

    std::time_t time = std::mktime(&tm);  // chuyển std::tm thành time_t
    return std::chrono::system_clock::from_time_t(time);  // chuyển time_t thành time_point
}

std::string trim(const std::string& s) {
    auto start = s.begin();
    while (start != s.end() && std::isspace(*start)) start++;

    auto end = s.end();
    do {
        end--;
    } while (std::distance(start, end) > 0 && std::isspace(*end));

    return std::string(start, end + 1);
}


//=============== Step 6===============:
ServiceTicket createServiceTicket(const std::string& clientID, const std::string& flags, const std::string& sessionKey,
    const std::string& clientAD, const std::string& realmc,
    const std::chrono::system_clock::time_point& from,
    const std::chrono::system_clock::time_point& till,
    const std::chrono::system_clock::time_point& rtime) {
    ServiceTicket ticket;
    ticket.clientID = clientID;
    ticket.flags = flags;
    ticket.sessionKey = sessionKey;
    ticket.clientAD = clientAD;
    ticket.realmc = realmc;
    ticket.timeInfo.from = from;
    ticket.timeInfo.till = till;
    ticket.timeInfo.rtime = rtime;
    return ticket;
}

// Lấy thời gian hiện tại
std::chrono::system_clock::time_point createTS2() {
    return std::chrono::system_clock::now();  
}
std::string timeToString(std::chrono::system_clock::time_point timePoint) {
    std::time_t timeT = std::chrono::system_clock::to_time_t(timePoint);

    // Khai báo mảng char đủ lớn để chứa chuỗi thời gian
    char buffer[100];

    // Sử dụng ctime_s để chuyển đổi thời gian
    ctime_s(buffer, sizeof(buffer), &timeT);

    return std::string(buffer);
}

// Hàm tạo Subkey sử dụng SHA-1
std::string createSubkey(const std::string& key, const std::string& data) { // data có thể là 1 dữ liệu bất kỳ, ở đây sẽ chọn data là TS2.
    std::string combined = key + data;
    std::string hash_result = sha1(combined);

    return hash_result;
}


// Hàm hỗ trợ: chuyển timestamp dạng chuỗi sang std::chrono::system_clock::time_point
chrono::system_clock::time_point millisecTimestampToTimePoint(const string& timestampStr) {
    uint64_t millisec = stoull(timestampStr);
    chrono::milliseconds dur(millisec);
    return chrono::system_clock::time_point(dur);
}

//Hàm lưu thông tin Ticket sau khi giải mã:
ServiceTicket parseServiceTicket(const string& decryptedText) {
    // Giả sử format: flags | sessionKey | realmc | clientID | clientAD | from | till | rtime
    vector<string> fields;
    stringstream ss(decryptedText);
    string item;

    while (getline(ss, item, '|')) {
        if (!item.empty()) {
            fields.push_back(item);
        }
    }

    // Kiểm tra số lượng thành phần của chuỗi
    if (fields.size() < 8) {
        throw runtime_error("parseServiceTicket: Invalid string format or missing element!");
    }

    // Tạo đối tượng ServiceTicket
    ServiceTicket ticket;
    ticket.flags = fields[0];
    ticket.sessionKey = fields[1];
    ticket.realmc = fields[2];
    ticket.clientID = fields[3];
    ticket.clientAD = fields[4];
    ticket.timeInfo.from = millisecTimestampToTimePoint(fields[5]);
    ticket.timeInfo.till = millisecTimestampToTimePoint(fields[6]);
    ticket.timeInfo.rtime = millisecTimestampToTimePoint(fields[7]);

    return ticket;
}

//Hàm in ServiceTicket:
void printServiceTicket(const ServiceTicket& ticket) {
    std::cout << "Flags      : " << ticket.flags << endl;
    std::cout << "SessionKey : " << ticket.sessionKey << endl;
    std::cout << "Realmc     : " << ticket.realmc << endl;
    std::cout << "ClientID   : " << ticket.clientID << endl;
    std::cout << "ClientAD   : " << ticket.clientAD << endl;

    auto tp_to_ms = [](chrono::system_clock::time_point tp) -> uint64_t {
        return chrono::duration_cast<chrono::milliseconds>(tp.time_since_epoch()).count();
        };

    std::cout << "Time From  : " << tp_to_ms(ticket.timeInfo.from) << endl;
    std::cout << "Time Till  : " << tp_to_ms(ticket.timeInfo.till) << endl;
    std::cout << "Time Rtime : " << tp_to_ms(ticket.timeInfo.rtime) << endl;
}

//hàm lưu giá trị vào AuthenticatorC sau khi giải mã:
AuthenticatorC parseAuthenticator(const string& decryptedText) {
    // Tách chuỗi decryptedText theo dấu '|'
    vector<string> fields;
    stringstream ss(decryptedText);
    string item;

    while (getline(ss, item, '|')) {
        if (!item.empty()) {
            fields.push_back(item);
        }
    }

    // Kiểm tra số lượng thành phần của chuỗi
    if (fields.size() < 5) {
        throw runtime_error("parseAuthenticator: Invalid string format or missing element!");
    }

    // Tạo đối tượng AuthenticatorC
    AuthenticatorC auth;
    auth.clientID = fields[0];
    auth.realmc = fields[1];
    auth.TS2 = millisecTimestampToTimePoint(fields[2]);
    auth.subkey = fields[3];
    auth.seqNum = stoi(fields[4]);  // Chuyển seqNum thành số

    return auth;
}

// Hàm tách chuỗi bằng dấu '|' và gán vào các biến
void splitAndAssign(const std::string& input, std::string& a, std::string& b, std::string& c) {
    std::stringstream ss(input);
    std::string token;
    int index = 0;

    while (std::getline(ss, token, '|')) {
        switch (index) {
        case 0: a = token; break;
        case 1: b = token; break;
        case 2: c = token; break;
        default: break; // Nếu có nhiều hơn 4 thành phần thì bỏ qua
        }
        ++index;
    }
}




uint64_t getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

// Hàm tạo plaintext từ các thông số nhập vào
std::string buildServiceTicketPlaintext(const std::string& flag,
    const std::string& sessionKey,
    const std::string& realmc,
    const std::string& clientID,
    const std::string& clientAD,
    uint64_t from, uint64_t till, uint64_t rtime) {

    // Ghép các giá trị thành chuỗi theo cấu trúc
    std::stringstream plaintext;
    plaintext << flag << "|"
        << sessionKey << "|"
        << realmc << "|"
        << clientID << "|"
        << clientAD << "|"
        << from << "|" << till << "|" << rtime;

    return plaintext.str();
}


std::string generate_nonce(int length) {
    std::random_device rd;
    std::mt19937 gen(rd()); 
    std::uniform_int_distribution<> dis(0, 255);

    std::stringstream nonce;
    for (int i = 0; i < length; ++i) {
        unsigned char byte = static_cast<unsigned char>(dis(gen));
        nonce << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return nonce.str();
}

// Hàm format thời gian thành string
std::string get_current_time_formatted() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&now_c), "%Y%m%d%H%M%S"); // format: YYYYMMDDhhmmss
    return ss.str();
}

std::string build_times(int ticket_lifetime, int renew_lifetime) {
    std::string from = get_current_time_formatted();

    // Till = From + ticket_lifetime tiếng (ticket có thể dùng trong ticket_lifetime tiếng)
    auto till_time = std::chrono::system_clock::now() + std::chrono::hours(ticket_lifetime);
    std::time_t till_c = std::chrono::system_clock::to_time_t(till_time);
    std::stringstream ss_till;
    ss_till << std::put_time(std::gmtime(&till_c), "%Y%m%d%H%M%S");
    std::string till = ss_till.str();

    // Rtime = Till + renew_lifetime tiếng (vé có thể gia hạn thêm renew_lifetime tiếng)
    auto rtime_time = till_time + std::chrono::hours(renew_lifetime);
    std::time_t rtime_c = std::chrono::system_clock::to_time_t(rtime_time);
    std::stringstream ss_rtime;
    ss_rtime << std::put_time(std::gmtime(&rtime_c), "%Y%m%d%H%M%S");
    std::string rtime = ss_rtime.str();

    // Ghép lại thành Times
    return from + "|" + till + "|" + rtime;
}


void send_message(SOCKET sock, const std::string& message)
{
    send(sock, message.c_str(), message.size(), 0);
}

void set_rec_time_out(SOCKET sock, int milliseconds) {
    DWORD timeout = milliseconds;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        throw std::runtime_error("Failed to set receive timeout.");
    }
}

std::string receive_message(SOCKET sock) {
    char buffer[4096];
    int bytesReceived = recv(sock, buffer, sizeof(buffer), 0);

    if (bytesReceived == 0) {
        throw std::runtime_error("Connection close by the peer.");
    }

    if (bytesReceived == SOCKET_ERROR) {
        int errorCode = WSAGetLastError();
        if (errorCode == WSAETIMEDOUT) {
            throw std::runtime_error("Receive timeout occurred.");
        }
        else {
            throw std::runtime_error("Receive failed with error code - " + std::to_string(errorCode));
        }
    }
    return std::string(buffer, bytesReceived);
}

/*
std::string receive_message(SOCKET sock) {
    char buffer[4096];
    int bytesReceived = recv(sock, buffer, sizeof(buffer), 0);
    if (bytesReceived == SOCKET_ERROR) {
        //throw std::runtime_error("Receive failed");
        std::cout << "RECEIVE MESSAGE FAILED!" << std::endl;
        return "RECEIVE MESSAGE FAILED!";
    }
    return std::string(buffer, bytesReceived);
}
*/

/*
void send_message(SOCKET sock, const std::string& message)
{
    std::string msg = message + "\n";
    send(sock, msg.c_str(), msg.size(), 0);
}

std::string receive_message(SOCKET sock) {
    std::string result;
    char ch;
    int bytesReceived;
    while (true) {
        bytesReceived = recv(sock, &ch, 1, 0);
        if (bytesReceived <= 0) break; // Lỗi hoặc đóng kết nối
        if (ch == '\n') break;         // Kết thúc message
        result += ch;
    }
    return result;
}
*/

// Hàm tạo chuỗi 16 ký tự ngẫu nhiên (dùng để tạo key và iv)
std::string generateRandomString(size_t length) {
    const std::string characters =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    // Dùng random_device để sinh seed ngẫu nhiên tốt hơn
    static std::random_device rd;
    static std::mt19937 engine(rd()); // Mersenne Twister engine
    std::uniform_int_distribution<size_t> dist(0, characters.size() - 1);

    std::string result;
    for (size_t i = 0; i < length; ++i) {
        result += characters[dist(engine)];
    }
    return result;
}


std::string extractAfterFirstDoublePipe(std::string& input) {
    size_t start = input.find("||");
    if (start == std::string::npos)
        throw std::invalid_argument("Cannot find '||' in input");

    size_t contentStart = start + 2; // Bỏ qua "||"
    size_t end = input.find("|", contentStart);
    if (end == std::string::npos)
        throw std::invalid_argument("Cannot find '|' after '||'");

    std::string result = input.substr(contentStart, end - contentStart);

    // Xóa chuỗi con + "||", KHÔNG xóa dấu '|'
    input.erase(start, contentStart - start + result.size());

    return result;
}

std::string extractAfterSecondDoublePipe(std::string& input) {
    size_t last = input.rfind("||");
    if (last == std::string::npos)
        throw std::invalid_argument("Cannot find last '||'");

    size_t start = last + 2;
    std::string result = input.substr(start);

    // Xóa phần "||" và chuỗi con phía sau nó
    input.erase(last);

    return result;
}

//check Time
std::string create_ticket_time(int ticket_lifetime, int renew_lifetime) {
    auto from_time = std::chrono::system_clock::now();
    std::time_t from_c = std::chrono::system_clock::to_time_t(from_time);

    // Till = From + ticket_lifetime tiếng (ticket có thể dùng trong ticket_lifetime tiếng)
    auto till_time = std::chrono::system_clock::now() + std::chrono::minutes(ticket_lifetime);
    std::time_t till_c = std::chrono::system_clock::to_time_t(till_time);


    // Rtime = Till + renew_lifetime tiếng (vé có thể gia hạn thêm renew_lifetime tiếng)
    auto rtime_time = till_time + std::chrono::minutes(renew_lifetime);
    std::time_t rtime_c = std::chrono::system_clock::to_time_t(rtime_time);

    // Ghép lại thành Times
    return std::to_string(from_c) + "|" + std::to_string(till_c) + "|" + std::to_string(rtime_c);
}

std::string check_ticket_time(std::string from, std::string till, std::string rtime) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    std::time_t from_c = static_cast<std::time_t>(std::stoll(from));
    std::time_t till_c = static_cast<std::time_t>(std::stoll(till));
    std::time_t rtime_c = static_cast<std::time_t>(std::stoll(rtime));

    if (now_c >= from_c && now_c <= till_c)
        return "VALID";
    else if (now_c >= till_c && now_c <= rtime_c)
        return "RENEW";
    else
        return "INVALID";
}

//hàm tạo option bước 5
uint32_t createAPOptions(bool useSessionKey, bool mutualRequired) {
    uint32_t options = 0;
    if (useSessionKey)
        options |= USE_SESSION_KEY;
    if (mutualRequired)
        options |= MUTUAL_REQUIRED;
    return options;
}

std::string apOptionsToBitString(uint32_t options) {
    std::bitset<32> bits(options);
    return bits.to_string(); // trả về chuỗi nhị phân dạng "011000...000"
}

bool checkAPOptionsFromBitString(const std::string& bitStr) {
    if (bitStr.length() != 32) {
        std::cerr << "Lỗi: Chuỗi APOptions không hợp lệ. Phải có 32 bit.\n";
        return false;
    }

    // Chuyển chuỗi nhị phân sang số uint32_t
    std::bitset<32> bits(bitStr);
    uint32_t options = static_cast<uint32_t>(bits.to_ulong());

    // Kiểm tra cả 2 bit đều bật hay không
    bool useSessionKey = (options & USE_SESSION_KEY) != 0;
    bool mutualRequired = (options & MUTUAL_REQUIRED) != 0;

    return (useSessionKey && mutualRequired);
}

//kiểm tra flag renewable
bool hasRenewableFlag(const std::string& bitString) {
    // Kiểm tra độ dài chuỗi phải là 32 ký tự (bitset<32>)
    if (bitString.length() != 32) return false;

    // RENEWABLE nằm ở bit số 30 từ trái sang phải (bit số 1 từ phải sang nếu tính theo giá trị enum)
    // Do std::bitset tạo chuỗi từ MSB -> LSB, ta cần truy cập đúng vị trí
    // Bit thấp nhất (LSB - vị trí 31) là bit 0 => RENEWABLE = 1 << 1 => vị trí 30
    return bitString[30] == '1';
}

//kiểm tra nếu Option là RENEW
bool isRenewOption(const std::string& bitString) {
    // Kiểm tra độ dài hợp lệ
    if (bitString.length() != 32) return false;

    // RENEW = 1 << 1 → bit số 1 → tương ứng vị trí 30 trong chuỗi
    // Vì std::bitset<32> tạo chuỗi theo thứ tự từ MSB đến LSB (bit 31 xuống bit 0)
    return bitString[30] == '1';
}

// Tạo option cho bước 1
uint32_t createOptions(bool initial, bool renew) {
    uint32_t options = 0;
    if (initial)
        options |= OP_INITIAL; //OR
    if (renew)
        options |= RENEW;
    return options;
}