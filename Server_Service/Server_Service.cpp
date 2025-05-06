#include "../Utils/Utils.h"

const int BLOCK_SIZE = 16;

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

int main() {
    WSADATA wsaData;
    SOCKET serviceSocket, clientSocket;
    sockaddr_in serviceAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[1024];

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    serviceSocket = socket(AF_INET, SOCK_STREAM, 0);
    serviceAddr.sin_family = AF_INET;
    serviceAddr.sin_addr.s_addr = INADDR_ANY;
    serviceAddr.sin_port = htons(8802);

    bind(serviceSocket, (sockaddr*)&serviceAddr, sizeof(serviceAddr));
    listen(serviceSocket, 5);

    cout << "Service Server listening on port 8802...\n";

    clientSocket = accept(serviceSocket, (sockaddr*)&clientAddr, &clientAddrLen);
    cout << "Client connected to Service Server.\n";

    // Nhận Service Ticket
    memset(buffer, 0, sizeof(buffer));
    recv(clientSocket, buffer, sizeof(buffer), 0);
    cout << "Received Service Ticket: " << buffer << "\n";

    // Gửi dịch vụ thực tế
    string serviceData = "Welcome! Here is your service data.";
    send(clientSocket, serviceData.c_str(), serviceData.length(), 0);

    closesocket(clientSocket);
    closesocket(serviceSocket);
    WSACleanup();
    return 0;
}
