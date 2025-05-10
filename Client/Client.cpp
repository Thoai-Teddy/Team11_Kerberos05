#include "../Utils/Utils.h"

const int BLOCK_SIZE = 16;

string OPTION = "";

SOCKET clientSocket; // Để đóng socket khi cần

// Hàm xử lý Ctrl+C
void handleCtrlC(int sig) {
    cout << "\nDisconnecting from server..." << endl;
    closesocket(clientSocket);
    WSACleanup();
    exit(0);
}

void sendToServer(SOCKET clientSocket, const string& message) {
    // Gửi dữ liệu tới server
    int messageLength = static_cast<int>(message.size());

    // Gửi thông điệp qua socket
    int result = send(clientSocket, message.c_str(), messageLength, 0);

    if (result == SOCKET_ERROR) {
        cerr << "Failed to send message to server. Error: " << WSAGetLastError() << endl;
        closesocket(clientSocket);  // Đảm bảo đóng socket khi có lỗi
        WSACleanup();
    }
    else {
        cout << "Message sent to server: " << message << endl;
    }
}


string createAuthenticator(const info& clientInfo, const string& subkey) {
    
    // Tạo đối tượng AuthenticatorC
    AuthenticatorC authenticator;
    authenticator.clientID = clientInfo.getID();  // ID của Client
    authenticator.realmc = clientInfo.getRealm(); // Realm của Client
    authenticator.TS2 = chrono::system_clock::now(); // Timestamp khi Client gửi yêu cầu
    authenticator.subkey = subkey;     // Subkey bảo vệ phiên giao dịch
    authenticator.seqNum = 1;         // Số thứ tự (có thể dùng cơ chế tăng dần cho mỗi lần gửi yêu cầu)

    // Chuyển đổi thời gian TS2 thành chuỗi (ví dụ sử dụng thời gian Unix timestamp)
    auto timestamp = chrono::duration_cast<chrono::seconds>(authenticator.TS2.time_since_epoch()).count();

    // Tạo chuỗi kết quả theo định dạng "clientID||realm||TS2||subkey||seqNum"
    return authenticator.clientID + "|" +
        authenticator.realmc + "|" +
        to_string(timestamp) + "|" +
        authenticator.subkey + "|" +
        to_string(authenticator.seqNum);
}


void processTGSResponse(
    const string& ticketV,
    const string& iv_ticketV,
    const string& kcv,
    const string& from_time,
    const string& till_time,
    const string& realmV,
    const string& idV,
    const info& clientInfo,
    const info& serverInfo,
    const string& iv
) {
    // Kiểm tra thông tin Server V
    if (realmV != serverInfo.getRealm() || idV != serverInfo.getID()) {
        throw invalid_argument("Realm or ID does not match server information");
    }

    //string now = get_current_time_formatted();

    //if (now < from_time) {
    //    throw invalid_argument("Ticket is not yet valid");
    //}
    //if (now > till_time) {
    //    throw invalid_argument("Ticket has expired");
    //}

    // Tạo AuthenticatorC: E(Kcv, [IDC || RealmC || TS2 || Subkey || Seq#])
    string authenticator = createAuthenticator(clientInfo, kcv);
    vector<unsigned char> authenticator_vec = padString(authenticator);

    // Chuẩn bị key và IV
    vector<unsigned char> kcv_vec(kcv.begin(), kcv.end());
    while (kcv_vec.size() < BLOCK_SIZE) kcv_vec.push_back(0x00);
    vector<unsigned char> iv_vec(iv.begin(), iv.end());

    vector<unsigned char> authenticator_en_vec = aes_cbc_encrypt(authenticator_vec, kcv_vec, iv_vec);
    string authenticator_en = bytesToHex(authenticator_en_vec);
    cout << "authenticator: " << authenticator << endl;
    // Tạo message gửi tới Server V
    string message = OPTION + "|" + ticketV + "||" + iv_ticketV + "|" + authenticator_en + "||" + iv;

    // Gửi nếu cần
    sendToServer(clientSocket, message);
}



string timePointToString(const chrono::system_clock::time_point& tp) {
    time_t time = chrono::system_clock::to_time_t(tp);
    tm* tm = localtime(&time);  // Chuyển đổi thành tm cấu trúc
    ostringstream oss;

    // Tạo chuỗi thời gian theo định dạng YYYY-MM-DD HH:MM:SS
    oss << (tm->tm_year + 1900) << "-"
        << (tm->tm_mon + 1) << "-"
        << tm->tm_mday << " "
        << tm->tm_hour << ":"
        << tm->tm_min << ":"
        << tm->tm_sec;

    return oss.str();
}

string decryptMessFromV(const string& encryptMess, const string& Kcv, const string& iv_str) {
    vector<unsigned char> cipherBytes = hexStringToVector(encryptMess);
    vector<unsigned char> key_vec(Kcv.begin(), Kcv.end());
    vector<unsigned char> ivBytes(iv_str.begin(), iv_str.end());

    vector<unsigned char> decryptedBytes = aes_cbc_decrypt(cipherBytes, key_vec, ivBytes);

    string decryptedText = unpadString(decryptedBytes);

    return decryptedText;
}


int main() {
    
    WSADATA wsaData;
    sockaddr_in serverAddr;
    char buffer[1024];

    // Bắt Ctrl+C
    signal(SIGINT, handleCtrlC);

    // Khởi tạo Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed." << endl;
        return 1;
    }

    // Tạo socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "Socket creation failed." << endl;
        WSACleanup();
        return 1;
    }

    // Cấu hình server
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8800); // Kết nối tới cổng 8800 của AS Server
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr); // Hoặc đổi IP khác nếu cần

    // Kết nối server
    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Connection to server failed." << endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    cout << "Connected to AS Server." << endl << endl;

    info client("IDCLient", "realmClient");
    info serverTGS("IDServerTGS", "RealmServerTGS");

    // Cấu hình các giá trị
    string Options = "auth";
    string Times = build_times(8, 24);
    string Nonce1 = generate_nonce(8); // Random 8 bytes

    string request = Options + "|" + client.getID() + "|" + client.getRealm() + "|" + serverTGS.getID() + "|" + Times + "|" + Nonce1;

    cout << "Sending Request: " << request << endl << endl;

    send_message(clientSocket, request);

    string response_from_as = receive_message(clientSocket);

    //Lấy iv
    string iv_tgs = "";
    try {
        iv_tgs = extractAfterFirstDoublePipe(response_from_as);
    }
    catch (const exception& ex) {
        cerr << "Error: " << ex.what() << endl;
    }

    string iv_pre = "";
    try {
        iv_pre = extractAfterSecondDoublePipe(response_from_as);
    }
    catch (const exception& ex) {
        cerr << "Error: " << ex.what() << endl << endl;
    }
    if (iv_pre.size() > BLOCK_SIZE) {
        iv_pre = iv_pre.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> iv(iv_pre.begin(), iv_pre.end());
    while (iv.size() < BLOCK_SIZE) iv.push_back(0x00); // Bổ sung nếu thiếu

    //message sau khi tách iv
    cout << "Response from AS: " << response_from_as << endl << endl;

    // Tách dữ liệu mà server trả về
    vector <string> response_part = splitString(response_from_as, "|");

    if (response_part.size() < 4)
    {
        cout << "Error: Response from AS Server is invalid!" << endl << endl;
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }

    string realm_c_from_as = response_part[0];
    string id_c_from_as = response_part[1];
    string ticket_tgs_from_as = response_part[2];
    string ciphertext_hex_from_as = response_part[3];
   
    vector<unsigned char> ciphertext_block_from_as = hexStringToVector(ciphertext_hex_from_as);
    
    // Lấy client_key
    string K_c = "TonightIWillSing";
    client.setPrivateKey(K_c);

    if (K_c.size() > BLOCK_SIZE) {
        K_c = K_c.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> key_client(K_c.begin(), K_c.end());
    while (key_client.size() < BLOCK_SIZE) key_client.push_back(0x00); // Bổ sung nếu thiếu

    // Giải mã
    vector<unsigned char> plaintext_block_from_as = aes_cbc_decrypt(ciphertext_block_from_as, key_client, iv);
    string plaintext_from_as = unpadString(plaintext_block_from_as);
    cout << "Plaintext after decrypted with K_c: " << plaintext_from_as << endl << endl;

    vector <string> parts_plaintext_from_as = splitString(plaintext_from_as, "|");
    
    string K_c_tgs = parts_plaintext_from_as[0];
    string from_time_from_as = parts_plaintext_from_as[1];
    string till_time_from_as = parts_plaintext_from_as[2];
    string rtime_time_from_as = parts_plaintext_from_as[3];
    string nonce1_from_as = parts_plaintext_from_as[4];
    string realm_tgs_from_as = parts_plaintext_from_as[5];
    string id_tgs_from_as = parts_plaintext_from_as[6];



    if (nonce1_from_as != Nonce1) {
        cout << "WARNING! DIFFERENT NONCE! THIS MAY BE A REPLAY ATTACK!" << endl << endl;
    }

    // Đóng kết nối với AS Server
    closesocket(clientSocket);

    /*
    auto now = chrono::system_clock::now();
    auto future = now + chrono::hours(1);  // Thời gian hết hạn là 1 giờ sau
    auto past = now - chrono::hours(1);
    auto nowTs = to_string(chrono::duration_cast<chrono::seconds>(now.time_since_epoch()).count());
    auto futureTs = to_string(chrono::duration_cast<chrono::seconds>(future.time_since_epoch()).count());
    auto pastTs = to_string(chrono::duration_cast<chrono::seconds>(past.time_since_epoch()).count());

    string plaintext = "khoaphienCServerV|" + nowTs + "|" + futureTs + "|" + pastTs + "|" + nowTs + "|" + "RealmServerV|IDServerV";
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
    string data = "realmClient|IDCLient|TicketServerVdamahoa|"  + cipher;
    cout << "data: " << data << endl;
    processTGSResponse(data, client, server, key_input, iv_pre);

    */

    
    // Kết nối tới TGS Server
    //Cấu hình
    info serverV("IDServerV", "RealmServerV");
    
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    serverAddr.sin_port = htons(8801); // Kết nối tới cổng 8801 của TGS Server

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Connection to TGS failed." << endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    // Gửi thông tin tới TGS Server theo dạng "Options|ID_V|Times|Nonce2|Ticket_TGS|Authenticatorc"
    //string Options = "auth";
	string Ticket_TGS = ticket_tgs_from_as;
    Times = build_times(8, 24);
    string Nonce2 = generate_nonce(8); // Random 8 bytes
    auto TS2 = chrono::system_clock::now();  // Giả sử TS2 là time_point hiện tại
    string TS2_str = timePointToString(TS2);  // Chuyển TS2 thành chuỗi
	string subkey = createSubkey(K_c_tgs, TS2_str);
    string Authenticatorc = createAuthenticator(client, subkey);
    string message_to_tgs = Options + "|" + serverV.getID() + "|" + Times + "|" + Nonce2 + "|" + Ticket_TGS + "||" + iv_tgs + "|" + Authenticatorc;
	cout << "Sending message to TGS: " << message_to_tgs << endl << endl;

    
    send_message(clientSocket, message_to_tgs);

    int bytesReceived = 0;

    // Nhận Service Ticket từ TGS Server
    memset(buffer, 0, sizeof(buffer)); // Clear buffer
    bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived > 0) {
        cout << "Received Service Ticket: " << buffer << endl << endl;
    }

    // Tách dữ liệu mà server trả về
    string response_tgs(buffer);
    // Tách iv để giải mã plaintext
    //string iv_pre_v = "ImAloneAndAboutY";
    string iv_pre_v = "";
    try {
        iv_pre_v = extractAfterSecondDoublePipe(response_tgs);
        cout << "iv_pre_v: " << iv_pre_v << endl;
    }
    catch (const exception& ex) {
        cerr << "Error: " << ex.what() << endl << endl;
    }
    if (iv_pre_v.size() > BLOCK_SIZE) {
        iv_pre_v = iv_pre_v.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> iv_v(iv_pre_v.begin(), iv_pre_v.end());

    while (iv_v.size() < BLOCK_SIZE) iv_v.push_back(0x00); // Bổ sung nếu thiếu

    //Tách iv TicketV
    string iv_ticket_v = "";
    try {
        iv_ticket_v = extractAfterFirstDoublePipe(response_tgs);
    }
    catch (const exception& ex) {
        cerr << "Error: " << ex.what() << endl << endl;
    }

    vector <string> response_tgs_part = splitString(response_tgs, "|");

    if (response_tgs_part.size() < 4)
    {
        cout << "Error: Response from AS Server is invalid!" << endl << endl;
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }

    string realm_c_from_tgs = response_tgs_part[0];
    string id_c_from_tgs = response_tgs_part[1];
    string ticket_v_from_tgs = response_tgs_part[2];
    string ciphertext_hex_from_tgs = response_tgs_part[3];

    vector<unsigned char> ciphertext_block_from_tgs = hexStringToVector(ciphertext_hex_from_tgs);


    // Giải mã
    if (K_c_tgs.size() > BLOCK_SIZE) {
        K_c_tgs = K_c_tgs.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> Key_c_tgs(K_c_tgs.begin(), K_c_tgs.end());

    while (Key_c_tgs.size() < BLOCK_SIZE) Key_c_tgs.push_back(0x00); // Bổ sung nếu thiếu

    vector<unsigned char> plaintext_block_from_tgs = aes_cbc_decrypt(ciphertext_block_from_tgs, Key_c_tgs, iv_v);
    string plaintext_from_tgs = unpadString(plaintext_block_from_tgs);
    cout << "Plaintext after decrypted with K_c_tgs: " << plaintext_from_tgs << endl << endl;

    vector <string> parts_plaintext_from_tgs = splitString(plaintext_from_tgs, "|");

    string K_c_v = parts_plaintext_from_tgs[0];
    string from_time_from_tgs = parts_plaintext_from_tgs[1];
    string till_time_from_tgs = parts_plaintext_from_tgs[2];
    string rtime_time_from_tgs = parts_plaintext_from_tgs[3];
    string nonce2_from_tgs = parts_plaintext_from_tgs[4];
    string realm_v_from_tgs = parts_plaintext_from_tgs[5];
    string id_v_from_tgs = parts_plaintext_from_tgs[6];



    if (nonce2_from_tgs != Nonce2) {
        cout << "WARNING! DIFFERENT NONCE! THIS MAY BE A REPLAY ATTACK!" << endl << endl;
    }

    // Đóng kết nối với TGS Server
    closesocket(clientSocket);

    if (realm_v_from_tgs != serverV.getRealm() || id_v_from_tgs != serverV.getID()) {
        throw invalid_argument("Realm or ID does not match server information");
    }

    // Kết nối tới Service Server
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    serverAddr.sin_port = htons(8802); // Kết nối tới cổng 8802 của Service Server

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Connection to Service Server failed." << endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    string iv_client_to_server = generateRandomString();

    cout << "iv_ticket_v: " << iv_ticket_v << endl;
    cout << "iv_c_t_s: " << iv_client_to_server << endl;

    processTGSResponse(ticket_v_from_tgs, iv_ticket_v, K_c_v, from_time_from_tgs, till_time_from_tgs, realm_v_from_tgs, id_v_from_tgs, client, serverV, iv_client_to_server);
    
    // Nhận dữ liệu phản hồi từ Service Server
    memset(buffer, 0, sizeof(buffer)); // Clear buffer
    bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived > 0) {
        cout << endl << "Receive from V: " << buffer << endl;
        
        string s(buffer);
        string iv_from_V = "";
        try {
            iv_from_V = extractAfterSecondDoublePipe(s);
        }
        catch (const exception& ex) {
            cerr << "Error: " << ex.what() << endl << endl;
        }

        string decryptedText = decryptMessFromV(s, K_c_v, iv_from_V);

        cout << endl << "Decrypt Mess from V: " << decryptedText << endl;
        cout << endl << "Kerberos 5 authentication complete!" << endl << endl;
    }
    else {
        cerr << "No response or error receiving from Service Server." << endl;
    }


    // Đóng kết nối với Service Server
    closesocket(clientSocket);
    WSACleanup();

    return 0;
}
