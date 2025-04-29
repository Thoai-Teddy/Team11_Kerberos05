#include "../Utils/Utils.h"

const int BLOCK_SIZE = 16;

std::string OPTION = "";

SOCKET clientSocket; // Để đóng socket khi cần

// Hàm xử lý Ctrl+C
void handleCtrlC(int sig) {
    cout << "\nDisconnecting from server..." << endl;
    closesocket(clientSocket);
    WSACleanup();
    exit(0);
}
/*
void sendToServer(SOCKET clientSocket, const std::string& message) {
    // Gửi dữ liệu tới server
    int messageLength = static_cast<int>(message.size());

    // Gửi thông điệp qua socket
    int result = send(clientSocket, message.c_str(), messageLength, 0);

    if (result == SOCKET_ERROR) {
        std::cerr << "Failed to send message to server. Error: " << WSAGetLastError() << std::endl;
        closesocket(clientSocket);  // Đảm bảo đóng socket khi có lỗi
        WSACleanup();
    }
    else {
        std::cout << "Message sent to server: " << message << std::endl;
    }
}
*/

std::string createAuthenticator(const info& clientInfo, const std::string& subkey) {
    // Tạo đối tượng AuthenticatorC
    AuthenticatorC authenticator;
    authenticator.clientID = clientInfo.getID();  // ID của Client
    authenticator.realmc = clientInfo.getRealm(); // Realm của Client
    authenticator.TS2 = std::chrono::system_clock::now(); // Timestamp khi Client gửi yêu cầu
    authenticator.subkey = subkey;     // Subkey bảo vệ phiên giao dịch
    authenticator.seqNum = 1;         // Số thứ tự (có thể dùng cơ chế tăng dần cho mỗi lần gửi yêu cầu)

    // Chuyển đổi thời gian TS2 thành chuỗi (ví dụ sử dụng thời gian Unix timestamp)
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(authenticator.TS2.time_since_epoch()).count();

    // Tạo chuỗi kết quả theo định dạng "clientID||realm||TS2||subkey||seqNum"
    return authenticator.clientID + "|" +
        authenticator.realmc + "|" +
        std::to_string(timestamp) + "|" +
        authenticator.subkey + "|" +
        std::to_string(authenticator.seqNum);
}


void processTGSResponse(const std::string& tgsResponse, const info& clientInfo, const info& serverInfo, const std::string& kcTgs, const std::string& iv) {
    // Tách chuỗi nhận được thành các thành phần
    std::vector<std::string> parts = splitString(tgsResponse, "|");

    if (parts.size() < 4) {
        throw std::invalid_argument("Invalid TGS response format");
    }

    // Phân tích từng thành phần
    std::string realmC = parts[0];
    std::string idC = parts[1];
    std::string ticketV = parts[2];
    std::string encryptedData = parts[3];

    vector<unsigned char> encryptedData_vec = hexStringToVector(encryptedData);
    if (realmC != clientInfo.getRealm() || idC != clientInfo.getID()) {
        throw std::runtime_error("Mismatch between TGS response and client information");
    }

    vector<unsigned char> kcTgs_vec(kcTgs.begin(), kcTgs.end());
    vector<unsigned char> iv_vec(iv.begin(), iv.end());

    // Giải mã E(Kc,tgs, [...])
    vector<unsigned char> decryptedData_vec = aes_cbc_decrypt(encryptedData_vec, kcTgs_vec, iv_vec);

    std::string decryptedData = unpadString(decryptedData_vec);

    // Tách dữ liệu đã giải mã
    std::vector<std::string> decryptedParts = splitString(decryptedData, "|");
    if (decryptedParts.size() < 7) {
        throw std::invalid_argument("Invalid decrypted data format");
    }

    std::string kcv = decryptedParts[0];
    std::string realmV = decryptedParts[5];  // Realm của Server V
    std::string idV = decryptedParts[6];     // ID của Server V

    // Kiểm tra xem realmV và idV có khớp với thông tin của serverV không
    if (realmV != serverInfo.getRealm() || idV != serverInfo.getID()) {
        throw std::invalid_argument("Realm or ID does not match server information");
    }

    // Phân tích các chuỗi thời gian từ decryptedParts
    std::chrono::system_clock::time_point from = std::chrono::system_clock::time_point(std::chrono::seconds(std::stoll(decryptedParts[1])));   // Thời gian bắt đầu hợp lệ
    std::chrono::system_clock::time_point till = std::chrono::system_clock::time_point(std::chrono::seconds(std::stoll(decryptedParts[2])));   // Thời gian hết hạn
    std::chrono::system_clock::time_point rtime = std::chrono::system_clock::time_point(std::chrono::seconds(std::stoll(decryptedParts[3])));  // Thời gian kiểm tra
    
    // Lấy thời gian hiện tại
    auto now = std::chrono::system_clock::now();

    // Kiểm tra xem vé có còn hợp lệ không
    if (now < from) {
        throw std::invalid_argument("Ticket is not yet valid");
    }
    if (now > till) {
        throw std::invalid_argument("Ticket has expired");
    }


    // Tạo đối tượng AuthenticatorC bằng cách gọi hàm riêng
    std::string authenticator = createAuthenticator(clientInfo, kcv);
    vector<unsigned char> authenticator_vec = padString(authenticator);
    if (kcv.size() > BLOCK_SIZE) {
        kcv = kcv.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> kcv_vec(kcv.begin(), kcv.end());
    while (kcv_vec.size() < BLOCK_SIZE) kcv_vec.push_back(0x00); // Bổ sung nếu thiếu

    vector<unsigned char> authenticator_en_vec = aes_cbc_encrypt(authenticator_vec, kcv_vec, iv_vec);

    std::string authenticator_en = bytesToHex(authenticator_en_vec);
    //// Tạo message gửi đi
    //std::string message = OPTION + "|" + ticketV + "|" + authenticator_en;

    //sendToServer(clientSocket, message);
}

std::string timePointToString(const std::chrono::system_clock::time_point& tp) {
    std::time_t time = std::chrono::system_clock::to_time_t(tp);
    std::tm* tm = std::localtime(&time);  // Chuyển đổi thành tm cấu trúc
    std::ostringstream oss;

    // Tạo chuỗi thời gian theo định dạng YYYY-MM-DD HH:MM:SS
    oss << (tm->tm_year + 1900) << "-"
        << (tm->tm_mon + 1) << "-"
        << tm->tm_mday << " "
        << tm->tm_hour << ":"
        << tm->tm_min << ":"
        << tm->tm_sec;

    return oss.str();
}


int main() {
    //WSADATA wsaData;
    //sockaddr_in serverAddr;
    //char buffer[1024];

    //// Bắt Ctrl+C
    //signal(SIGINT, handleCtrlC);

    //// Khởi tạo Winsock
    //if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    //    cerr << "WSAStartup failed." << endl;
    //    return 1;
    //}

    //// Tạo socket
    //clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    //if (clientSocket == INVALID_SOCKET) {
    //    cerr << "Socket creation failed." << endl;
    //    WSACleanup();
    //    return 1;
    //}

    //// Cấu hình server
    //serverAddr.sin_family = AF_INET;
    //serverAddr.sin_port = htons(8800); // Kết nối tới cổng 8800 của AS Server
    //inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr); // Hoặc đổi IP khác nếu cần

    //// Kết nối server
    //if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
    //    cerr << "Connection to server failed." << endl;
    //    closesocket(clientSocket);
    //    WSACleanup();
    //    return 1;
    //}

    //cout << "Connected to AS Server." << endl;

    //// Gửi username tới AS Server
    //cout << "Enter username: ";
    //cin.getline(buffer, sizeof(buffer));
    //send(clientSocket, buffer, strlen(buffer), 0);

    //// Nhận TGT từ AS Server
    //memset(buffer, 0, sizeof(buffer)); // Clear buffer
    //int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    //if (bytesReceived > 0) {
    //    cout << "Received TGT: " << buffer << endl;
    //}

    //// Đóng kết nối với AS Server
    //closesocket(clientSocket);

    //// Kết nối tới TGS Server
    //clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    //serverAddr.sin_port = htons(8801); // Kết nối tới cổng 8801 của TGS Server

    //if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
    //    cerr << "Connection to TGS failed." << endl;
    //    closesocket(clientSocket);
    //    WSACleanup();
    //    return 1;
    //}

    //// Gửi TGT tới TGS Server
    //send(clientSocket, buffer, strlen(buffer), 0);

    //// Nhận Service Ticket từ TGS Server
    //memset(buffer, 0, sizeof(buffer)); // Clear buffer
    //bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    //if (bytesReceived > 0) {
    //    cout << "Received Service Ticket: " << buffer << endl;
    //}

    //// Đóng kết nối với TGS Server
    //closesocket(clientSocket);

    //// Kết nối tới Service Server
    //clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    //serverAddr.sin_port = htons(8802); // Kết nối tới cổng 8802 của Service Server

    //if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
    //    cerr << "Connection to Service Server failed." << endl;
    //    closesocket(clientSocket);
    //    WSACleanup();
    //    return 1;
    //}

    //// Gửi Service Ticket tới Service Server
    //send(clientSocket, buffer, strlen(buffer), 0);

    //// Nhận dữ liệu từ Service Server
    //memset(buffer, 0, sizeof(buffer)); // Clear buffer
    //bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    //if (bytesReceived > 0) {
    //    cout << "Received Service Data: " << buffer << endl;
    //}

    //// Đóng kết nối với Service Server
    //closesocket(clientSocket);
    //WSACleanup();
    auto now = std::chrono::system_clock::now();
    auto future = now + std::chrono::hours(1);  // Thời gian hết hạn là 1 giờ sau
    auto past = now - std::chrono::hours(1);
    auto nowTs = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
    auto futureTs = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(future.time_since_epoch()).count());
    auto pastTs = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(past.time_since_epoch()).count());

    std::string plaintext = "khoaphienCServerV|" + nowTs + "|" + futureTs + "|" + pastTs + "|" + nowTs + "|" + "RealmServerV|IDServerV";
    cout << "plaintext: " << plaintext << endl;
    string key_input = "khoaphienCTGS123";

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

    // Padding plaintext
    vector<unsigned char> padded_plaintext = padString(plaintext);

    // Mã hóa
    vector<unsigned char> ciphertext = aes_cbc_encrypt(padded_plaintext, key, iv);
    string cipher = bytesToHex(ciphertext);

    // In ciphertext dạng hex
    cout << "Ciphertext (hex): ";
    for (unsigned char c : ciphertext) {
        printf("%02X", c);
    }
    cout << "cipher: " << cipher << endl;
    cout << endl;

    info client("IDCLient", "realmClient");
    info server("IDServerV", "RealmServerV");
    std::string data = "realmClient|IDCLient|TicketServerVdamahoa|"  + cipher;
    cout << "data: " << data << std::endl;
    processTGSResponse(data, client, server, key_input, iv_pre);
    return 0;
}
