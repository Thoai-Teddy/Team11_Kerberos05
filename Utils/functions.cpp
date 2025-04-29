#include "./Utils.h"

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
    cout << "Flags      : " << ticket.flags << endl;
    cout << "SessionKey : " << ticket.sessionKey << endl;
    cout << "Realmc     : " << ticket.realmc << endl;
    cout << "ClientID   : " << ticket.clientID << endl;
    cout << "ClientAD   : " << ticket.clientAD << endl;

    auto tp_to_ms = [](chrono::system_clock::time_point tp) -> uint64_t {
        return chrono::duration_cast<chrono::milliseconds>(tp.time_since_epoch()).count();
        };

    cout << "Time From  : " << tp_to_ms(ticket.timeInfo.from) << endl;
    cout << "Time Till  : " << tp_to_ms(ticket.timeInfo.till) << endl;
    cout << "Time Rtime : " << tp_to_ms(ticket.timeInfo.rtime) << endl;
}

string authenTicketAndTakeSessionKey(const string& encryptTicket, const info& client, const string& iv, const string& priKeyV) {
    // Bước 1: Chuyển encryptTicket thành vector<unsigned char>
    vector<unsigned char> cipherBytes = hexStringToVector(encryptTicket);

    // Bước 2: Chuyển priKeyV và iv sang vector<unsigned char>
    vector<unsigned char> key(priKeyV.begin(), priKeyV.end());
    vector<unsigned char> ivBytes(iv.begin(), iv.end());

    // Bước 3: Giải mã AES-CBC
    vector<unsigned char> decryptedBytes = aes_cbc_decrypt(cipherBytes, key, ivBytes);

    // Bước 4: Bỏ padding để lấy chuỗi gốc
    string decryptedText = unpadString(decryptedBytes);

    // Bước 5: Parse ServiceTicket
    ServiceTicket ticket = parseServiceTicket(decryptedText);

    // Bước 6: Xác thực
    if (ticket.clientID != client.getID()) {
        return "mismatch!";
    }
    if (ticket.clientAD != client.getAD()) {
        return "mismatch!";
    }
    if (ticket.realmc != client.getRealm()) {
        return "mismatch!";
    }

    auto now = chrono::system_clock::now();
    if (now < ticket.timeInfo.from || now > ticket.timeInfo.till) {
        return "mismatch!";
    }

    return ticket.sessionKey;
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



string authenAuthenticatorAndGetSubkey(const string& encryptAuthenticator, const info& client, const string& iv, const string& priKeyV) {
    vector<unsigned char> cipherBytes = hexStringToVector(encryptAuthenticator);
    vector<unsigned char> key_vec(priKeyV.begin(), priKeyV.end());
    vector<unsigned char> ivBytes(iv.begin(), iv.end());

    vector<unsigned char> decryptedBytes = aes_cbc_decrypt(cipherBytes, key_vec, ivBytes);

    string decryptedText = unpadString(decryptedBytes);

    AuthenticatorC auth = parseAuthenticator(decryptedText);

    if (auth.clientID != client.getID()) {
        return "mismatch!";
    }
    if (auth.realmc != client.getRealm()) {
        return "mismatch!";
    }

    auto now = chrono::system_clock::now();
    /*if (now < auth.TS2) {
        return "Timestamp is too early!";
    }*/
    // In TS2 và giờ hiện tại (an toàn theo chuẩn C++)
    time_t now_c = chrono::system_clock::to_time_t(now);
    time_t ts2_c = chrono::system_clock::to_time_t(auth.TS2);

    tm now_tm, ts2_tm;
    localtime_s(&now_tm, &now_c);
    localtime_s(&ts2_tm, &ts2_c);

    // Kiểm tra lệch thời gian cho phép
    const int allowedSkewSeconds = 300; // 5 phút
    auto diff = chrono::duration_cast<chrono::seconds>(now - auth.TS2).count();

    if (abs(diff) > allowedSkewSeconds) {
        return "mismatch!";
    }

    return auth.subkey;
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

// Hàm tạo tin nhắn của Service server gửi cho Client
std::string createServerServiceMessage(const ServiceServerData& service, const std::string subKey) {
    // Chuyển TS2 thành chuỗi theo định dạng millisecond
    auto ts2Millisec = std::chrono::duration_cast<std::chrono::milliseconds>(service.TS2.time_since_epoch()).count();

    // Chuyển seqNum thành chuỗi
    std::ostringstream oss;
    oss << ts2Millisec << "|" << subKey << "|" << service.seqNum;

    // Trả về chuỗi đã kết hợp
    return oss.str();
}

string encryptServerServiceData(const ServiceServerData& service, const string subKey, string iv_str, string sessionKey) {
    string message = createServerServiceMessage(service, subKey);

    if (sessionKey.size() > BLOCK_SIZE) {
        sessionKey = sessionKey.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> key(sessionKey.begin(), sessionKey.end());
    while (key.size() < BLOCK_SIZE) key.push_back(0x00); // Bổ sung nếu thiếu

    if (iv_str.size() > BLOCK_SIZE) {
        iv_str = iv_str.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> iv(iv_str.begin(), iv_str.end());
    while (iv.size() < BLOCK_SIZE) iv.push_back(0x00); // Bổ sung nếu thiếu

    // Padding plaintext
    vector<unsigned char> padded_plaintext = padString(message);

    // Mã hóa
    vector<unsigned char> ciphertext = aes_cbc_encrypt(padded_plaintext, key, iv);
    string cipher = bytesToHex(ciphertext);

    return cipher;
}

//Hàm chính của step 6
string processServiceResponse(const ServiceServerData& service, const string& decryptMessage, const info& client, const string& ivTicket,
    const string& ivAuth, const string& priKeyV, string iv) {
    string cipherTicket, options, authen;
    string encryptMessage = "";

    splitAndAssign(decryptMessage, options, cipherTicket, authen);

    string sessionKey = authenTicketAndTakeSessionKey(cipherTicket, client, ivAuth, priKeyV);
    if (sessionKey == "mismatch!") return "Invalid information in Ticket!";
    else {
        string subKey = authenAuthenticatorAndGetSubkey(authen, client, ivTicket, sessionKey);        
        if (subKey == "mismatch!") return "Invalid information in Authenticator!";
        else {
            encryptMessage = encryptServerServiceData(service, subKey, iv, sessionKey);
        }
    }

    return encryptMessage;
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

std::string receive_message(SOCKET sock) {
    char buffer[4096];
    int bytesReceived = recv(sock, buffer, sizeof(buffer), 0);
    if (bytesReceived == SOCKET_ERROR) {
        throw std::runtime_error("Receive failed");
    }
    return std::string(buffer, bytesReceived);
}

/*
int main() {
   std::string clientID1 = "client123";
   std::string encryptedData = "encryptedData";
   std::chrono::system_clock::time_point TS2 = std::chrono::system_clock::now();
   std::string subkey = "subkey123";
   uint32_t seqNum = 1001;
   std::string kcV = "kcV123";

   ServiceServerData service(clientID1, encryptedData, TS2, subkey, seqNum, kcV);

   using namespace std::chrono;
   auto now = system_clock::now();
   auto millis = duration_cast<milliseconds>(now.time_since_epoch()).count();
    string plaintext = "client123|realmA|" + to_string(millis) +"| subkey123 | 12345";


    std::string flag = "01";                // Flag
    std::string sessionKey = "sessionKey123"; // Kc,v
    std::string realmc = "realmA";            // Realmc
    std::string clientID = "client123";       // IDC
    std::string clientAD = "127.0.0.1";       // ADC

    string iv_str = "1234567890abcdef";
    string encryptMess = encryptServerServiceData(service, subkey, iv_str, sessionKey);
    cout << "encrypt Mess: " << encryptMess << endl << endl;

     /*Lấy thời gian hiện tại*/
    uint64_t currentTime = getCurrentTimestamp();

     /*Giả sử:
     - `from` là thời gian hiện tại
     - `till` là 1 giờ sau
     - `rtime` là 2 giờ sau*/
    uint64_t from = currentTime;
    uint64_t till = currentTime + 3600000;  // 1 giờ sau
    uint64_t rtime = currentTime + 7200000; // 2 giờ sau

    /* Tạo plaintext từ các tham số trên*/
    /*std::string plaintext = buildServiceTicketPlaintext(flag, sessionKey, realmc, clientID, clientAD, from, till, rtime);*/

    /* In plaintext ra màn hình*/
    std::cout << "Generated Plaintext: " << plaintext << std::endl;


    string key_input = "privateKey1231111";

    if (key_input.size() > BLOCK_SIZE) {
        key_input = key_input.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> key(key_input.begin(), key_input.end());
    while (key.size() < BLOCK_SIZE) key.push_back(0x00); // Bổ sung nếu thiếu

    string iv_pre = "1234567890abcdef";
    if (iv_pre.size() > BLOCK_SIZE) {
        iv_pre = iv_pre.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> iv(iv_pre.begin(), iv_pre.end());
    while (iv.size() < BLOCK_SIZE) iv.push_back(0x00); // Bổ sung nếu thiếu

    /*Padding plaintext*/
    vector<unsigned char> padded_plaintext = padString(plaintext);

     /*Mã hóa*/
    vector<unsigned char> ciphertext = aes_cbc_encrypt(padded_plaintext, key, iv);
    string cipher = bytesToHex(ciphertext);

    cout << "cipher after string:" << cipher << endl;

     /*In ciphertext dạng hex*/
    cout << "Ciphertext (hex): ";
    for (unsigned char c : ciphertext) {
        printf("%02X", c);
    }
    cout << endl;

    string k = unpadString2(key);
    string i = unpadString2(iv);
    cout << "key string: " << k << endl << "iv string: " << i << endl;

    key = padString(k);
    iv = padString(i);

     /*Giải mã*/
    vector<unsigned char> decrypted_padded_plaintext = aes_cbc_decrypt(ciphertext, key, iv);

     /*Gỡ padding*/
    string decrypted_plaintext = unpadString(decrypted_padded_plaintext);

    /* In plaintext sau giải mã*/
    cout << "Plaintext sau khi giai ma: " << decrypted_plaintext << endl;

    info client("client123", "127.0.0.1", "realmA", "sessionKey123111", "privateKey123");

    /* Kiểm tra hàm*/
    try {
        string subkey = authenAuthenticatorAndGetSubkey(cipher, client, iv_pre, key_input);
        cout << "Subkey: " << subkey << endl;

        /*string sessionKey = authenTicketAndTakeSessionKey(cipher, client, iv_pre, key_input);
        cout << "Session Key: " << sessionKey << endl;*/

       /* cout << endl << "start decrypt test:" << endl;

        vector<unsigned char> cipherBytes = hexStringToVector(cipher);
        vector<unsigned char> key_vec(k.begin(), k.end());
        vector<unsigned char> ivBytes(i.begin(), i.end());
        vector<unsigned char> decryptedBytes = aes_cbc_decrypt(cipherBytes, key_vec, ivBytes);
        string deText = unpadString(decryptedBytes);
        cout << "result: " << deText << endl;*/
    }
    catch (const exception& e) {
        cout << "Error: " << e.what() << endl;
    }

    return 0;
}
*/

////Test tạo Message của Service Server
    //// Tạo một đối tượng ServiceServerData với thông tin giả lập
    //std::string clientID1 = "client123";
    //std::string encryptedData = "encryptedData";
    //std::chrono::system_clock::time_point TS2 = std::chrono::system_clock::now();
    //std::string subkey = "subkey123";
    //uint32_t seqNum = 1001;
    //std::string kcV = "kcV123";

    //ServiceServerData service(clientID1, encryptedData, TS2, subkey, seqNum, kcV);

    //// Gọi hàm createServerServiceMessage để tạo tin nhắn
    //std::string message = createServerServiceMessage(service, subkey);

    //// In ra tin nhắn đã tạo
    //cout << "Server Service Message: " << message << endl;

//int main() {   
//    //test hàm xác minh authenticator và lấy subKey
//    string encryptAuthenticator = "client123|realmA|1714300000000|subkey123|12345";  // Chuỗi mã hóa mẫu
//    string iv = "1234567890abcdef";  // IV giả lập
//    string priKeyV = "privateKey123"; // Private key giả lập
//
//    vector<unsigned char> iv_vec = padString(iv);
//    vector<unsigned char> priKeyV_vec = padString(priKeyV);
//    vector<unsigned char> padded_plaintext = padString(encryptAuthenticator);
//
//    // Mã hóa
//    vector<unsigned char> ciphertext = aes_cbc_encrypt(padded_plaintext, priKeyV_vec, iv_vec);
//    string padding_cipher = unpadString(ciphertext);
//
//    cout << "cipher: " << padding_cipher << endl;
//
//    info client("client123", "127.0.0.1", "realmA", "publicKey123", "privateKey123");
//
//    // Kiểm tra hàm
//    try {
//        string subkey = authenAuthenticatorAndGetSubkey(padding_cipher, client, iv, priKeyV);
//        cout << "Subkey: " << subkey << endl;
//    }
//    catch (const exception& e) {
//        cout << "Error: " << e.what() << endl;
//    }
//
//    return 0;
//}


//Test các hảm parse thông tin từ Ticket và Authenticator
//chrono::system_clock::time_point tnow = createTS2();
//string stime = timeToString(tnow);
//cout << "TS2: " << stime << endl;
//
//string key = "mysecretkey";
//// Tạo subkey
//string subkey = createSubkey(key, stime);
//cout << "Subkey: " << subkey << endl << endl;
//
//string decryptedText = "OK|abcdef1234567890abcdef|REALM.COM|user01|192.168.1.100|1714300000000|1714400000000|1714500000000";
//
//try {
//    ServiceTicket ticket = parseServiceTicket(decryptedText);
//    cout << "Parse success! Print data of ServiceTicket:" << endl;
//    printServiceTicket(ticket);
//    cout << endl;
//}
//catch (const exception& e) {
//    cerr << "Error: " << e.what() << endl;
//}
//
//string deText = "client123|realmA|1714300000000|subkey123|12345";
//
//try {
//    AuthenticatorC auth = parseAuthenticator(deText);
//
//    cout << "Print Authen:" << endl;
//    // In ra các giá trị đã tách
//    cout << "clientID: " << auth.clientID << endl;
//    cout << "realm: " << auth.realmc << endl;
//    cout << "TS2: " << chrono::system_clock::to_time_t(auth.TS2) << endl;
//    cout << "subkey: " << auth.subkey << endl;
//    cout << "seqNum: " << auth.seqNum << endl;
//}
//catch (const exception& e) {
//    cout << "Error: " << e.what() << endl;
//}