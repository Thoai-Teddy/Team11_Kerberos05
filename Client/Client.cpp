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
        cout << "Failed to send message to server. Error: " << WSAGetLastError() << endl;
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

    // Tạo chuỗi kết quả theo định dạng "clientID|realm|TS2|subkey|seqNum"
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

    uint32_t apOptions = createAPOptions(true, true);
    string OPTION = apOptionsToBitString(apOptions);

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


string encryptAuthenticatorc(const string& Mess, const string& Kc_tgs, const string& iv_authen) {
    vector<unsigned char> cipherBytes = hexStringToVector(Mess);
    vector<unsigned char> key(Kc_tgs.begin(), Kc_tgs.end());
    vector<unsigned char> ivBytes(iv_authen.begin(), iv_authen.end());

    vector<unsigned char> padded_ = padString(Mess);
    vector<unsigned char> encryptedBytes = aes_cbc_encrypt(padded_, key, ivBytes);
    string  encryptedText = bytesToHex(encryptedBytes);



    return encryptedText;
}

bool receive_and_parse_message(SOCKET clientSocket, std::vector<std::string>& parts, int parts_count) {
    try {
        std::string message = receive_message(clientSocket);
        std::cout << "Message receive: " << message << std::endl;
        parts = splitString(message, "|");
        if (parts.size() < parts_count) {
            //send_message(clientSocket, "INVALID MESSAGE REQUEST FORMAT!");
            return false;
        }
        return true;
    }
    catch (const std::exception& e) {
        std::cout << "Receive message failed: " << e.what() << std::endl;
        //return false;
        throw;
    }
}

int main() {

    WSADATA wsaData;
    sockaddr_in serverAddr;
    char buffer[1024];

    // Bắt Ctrl+C
    signal(SIGINT, handleCtrlC);

    // Khởi tạo Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cout << "WSAStartup failed." << std::endl;
        return 1;
    }

    // Tạo socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cout << "Socket creation failed." << std::endl;
        WSACleanup();
        return 1;
    }

    // Cấu hình server
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8800); // Kết nối tới cổng 8800 của AS Server
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr); // Hoặc đổi IP khác nếu cần

    // Kết nối server
    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cout << "Connection to server failed." << endl;
        WSACleanup();
        return 1;
    }

    std::cout << "Connected to AS Server." << endl << endl;

    //================ Dang nhap ================
    std::cout << "================ Dang nhap ================" << std::endl;
    // Nhập username và password
    std::string username = "";
    std::string password = "";

    std::cout << "Enter your username: ";
    getline(cin, username);

    std::cout << "Enter your password: ";
    getline(cin, password);

    // Gửi username cho AS
    send_message(clientSocket, username);

    // Nhận message log in từ AS
    std::string response_log_in_from_as;
    try {
        response_log_in_from_as = receive_message(clientSocket);
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }

    std::cout << "Response log in from AS: " << response_log_in_from_as << std::endl;
    if (response_log_in_from_as == "INVALID USERNAME!") {
        std::cout << "Error: Username is not exist!" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }

    // Tách message thành ciphertext và iv
    std::vector <std::string> log_in_response_part = splitString(response_log_in_from_as, "|");
    std::string log_in_ciphertext = log_in_response_part[0];
    std::string log_in_iv = log_in_response_part[1];
    std::cout << "Log in ciphertext: " << log_in_ciphertext << std::endl;
    std::cout << "Log in iv: " << log_in_iv << std::endl;

    // Hashpassword để lấy key giải mã
    std::string hashed_pass = sha1(password);
    std::cout << "Hashed pass: " << hashed_pass << std::endl;

    if (hashed_pass.size() > BLOCK_SIZE) {
        hashed_pass = hashed_pass.substr(0, BLOCK_SIZE);
    }
    std::cout << "Hashed pass after substr: " << hashed_pass << std::endl;

    vector<unsigned char> hashed_pass_vec(hashed_pass.begin(), hashed_pass.end());
    while (hashed_pass_vec.size() < BLOCK_SIZE) hashed_pass_vec.push_back(0x00);


    // Vector iv
    if (log_in_iv.size() > BLOCK_SIZE) {
        log_in_iv = log_in_iv.substr(0, BLOCK_SIZE);
    }

    std::cout << "Log in IV after substr: " << log_in_iv << std::endl;

    std::vector<unsigned char> log_in_iv_vec(log_in_iv.begin(), log_in_iv.end());
    while (log_in_iv_vec.size() < BLOCK_SIZE) log_in_iv_vec.push_back(0x00);


    // Vector ciphertext
    std::vector<unsigned char> log_in_ciphertext_vec = hexStringToVector(log_in_ciphertext);

    // Giải mã
    std::vector<unsigned char> log_in_plaintext_vec;
    try {
        log_in_plaintext_vec = aes_cbc_decrypt(log_in_ciphertext_vec, hashed_pass_vec, log_in_iv_vec);
    }
    catch (exception& e) {
        std::cout << "Error: Log in failed!" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        //return -1;
        exit(-1);
    }

    string log_in_plaintext = unpadString(log_in_plaintext_vec);
    std::cout << "Log in successfully." << std::endl;

    // Thông tin client
    std::string realm_c = "Kerberos05.com";
    std::string ad_c = "192.168.1.102";

    info client(username, realm_c, ad_c, "", hashed_pass);
    info serverTGS("tgs001", "Kerberos05.com");

    //======= Bước 1: Client gửi yêu cầu đến AS xin cấp vé TGT ======
    std::cout << std::endl << "======= Buoc 1: Client gui yeu cau den AS xin cap ve TGT ======" << std::endl;

    // Cấu hình các giá trị
    // Option có renewable và initial
    uint32_t options_uint = createOptions(true, true);
    std::string options = apOptionsToBitString(options_uint);
    std::string times = create_ticket_time(3, 5);
    std::string nonce1 = generate_nonce(8); // Random 8 bytes

    std::string request_tgt = options + "|" + client.getID() + "|" + client.getRealm() + "|" + serverTGS.getID() + "|" + times + "|" + nonce1;

    std::cout << "Sending Request To AS: " << request_tgt << std::endl << std::endl;
    // Gửi request xin cấp vé đến AS
    send_message(clientSocket, request_tgt);

    //======= Bước 2: Nhận message mà AS trả về ======
    std::cout << std::endl << "======= Buoc 2: Client nhan phan hoi ve TGT tu AS ======" << std::endl;

    // Nhận message AS trả về
    std::string response_from_as;
    try {
        response_from_as = receive_message(clientSocket);
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }
    std::cout << "Response From AS About TGT: " << response_from_as << std::endl << std::endl;


    if (response_from_as == "WRONG ID!") {
        std::cout << "Error: Wrong id!" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }

    if (response_from_as == "QUERY ADC FAILED!") {
        std::cout << "Error: Query ADC failed!" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }

    if (response_from_as == "TICKET EXPIRED!") {
        std::cout << "Error: Ticket expired!" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }

    if (response_from_as == "ID TGS WRONG!") {
        std::cout << "Error: ID tgs is wrong!" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }

    // Tách dữ liệu mà AS trả về
    std::vector <std::string> as_response_part = splitString(response_from_as, "|");

    if (as_response_part.size() < 6)
    {
        cout << "Error: Response from AS Server is invalid!" << endl << endl;
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }

    std::string realm_c_from_as = as_response_part[0];
    std::string id_c_from_as = as_response_part[1];
    std::string ticket_tgs_from_as = as_response_part[2];
    std::string iv_for_tgs_ticket = as_response_part[3];
    std::string ciphertext_hex_from_as = as_response_part[4];
    std::string iv_for_message_from_as = as_response_part[5];

    std::vector<unsigned char> ciphertext_vec_from_as = hexStringToVector(ciphertext_hex_from_as);

    std::vector<unsigned char> iv_vector_for_message_from_as(iv_for_message_from_as.begin(), iv_for_message_from_as.end());
    while (iv_vector_for_message_from_as.size() < BLOCK_SIZE) iv_vector_for_message_from_as.push_back(0x00); // Bổ sung nếu thiếu

    // Giải mã (client key để giải mã là hashed_pass_vec đã xử lý lúc đăng nhập)
    std::vector<unsigned char> plaintext_vec_from_as = aes_cbc_decrypt(ciphertext_vec_from_as, hashed_pass_vec, iv_vector_for_message_from_as);
    std::string plaintext_from_as = unpadString(plaintext_vec_from_as);

    std::cout << "Plaintext after decrypted with K_c: " << plaintext_from_as << std::endl << std::endl;

    std::vector <std::string> plaintext_parts_from_as = splitString(plaintext_from_as, "|");

    std::string K_c_tgs = plaintext_parts_from_as[0];
    std::string from_time_from_as = plaintext_parts_from_as[1];
    std::string till_time_from_as = plaintext_parts_from_as[2];
    std::string rtime_time_from_as = plaintext_parts_from_as[3];
    std::string nonce1_from_as = plaintext_parts_from_as[4];
    std::string realm_tgs_from_as = plaintext_parts_from_as[5];
    std::string id_tgs_from_as = plaintext_parts_from_as[6];

    if (nonce1_from_as != nonce1) {
        std::cout << "WARNING! DIFFERENT NONCE! THIS MAY BE A REPLAY ATTACK!" << endl << endl;
    }

    // Đóng kết nối với AS Server
    closesocket(clientSocket);
    WSACleanup();

    return 0;
}

/*

    // Kết nối tới TGS Server
    //Cấu hình
    info serverV("IDServerV", "RealmServerV");

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    serverAddr.sin_port = htons(8801); // Kết nối tới cổng 8801 của TGS Server

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cout << "Connection to TGS failed." << endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    // Gửi thông tin tới TGS Server theo dạng "Options|ID_V|Times|Nonce2|Ticket_TGS|Authenticatorc|iv_authen"
    //string Options = "auth";
    string Ticket_TGS = ticket_tgs_from_as;
    times = build_times(8, 24);
    string Nonce2 = generate_nonce(8); // Random 8 bytes
    auto TS2 = chrono::system_clock::now();  // Giả sử TS2 là time_point hiện tại
    string TS2_str = timePointToString(TS2);  // Chuyển TS2 thành chuỗi
    string subkey = createSubkey(K_c_tgs, TS2_str);
    string Authenticatorc = createAuthenticator(client, subkey);

    //Mã hóa Authenticatorc 
    string iv_authen = generateRandomString();
    cout << "iv_authen: " << iv_authen << endl << endl;
    string encrypted_authenticator = encryptAuthenticatorc(Authenticatorc, K_c_tgs, iv_authen);
    string message_to_tgs = options + "|" + serverV.getID() + "|" + times + "|" + Nonce2 + "|" + Ticket_TGS + "||" + iv_for_tgs_ticket + "|" + encrypted_authenticator + "||" + iv_authen;
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
        cout << "Error: " << ex.what() << endl << endl;
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
        cout << "Error: " << ex.what() << endl << endl;
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
        cout << "Connection to Service Server failed." << endl;
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
        string s(buffer);
        size_t pos = s.find('|');
        if (pos != std::string::npos) {
            cout << endl << "Receive from V: " << buffer << endl;


            string iv_from_V = "";
            try {
                iv_from_V = extractAfterSecondDoublePipe(s);
            }
            catch (const exception& ex) {
                cout << "Error: " << ex.what() << endl << endl;
            }

            string decryptedText = decryptMessFromV(s, K_c_v, iv_from_V);

            cout << endl << "Decrypt Mess from V: " << decryptedText << endl;
            cout << endl << "Kerberos 5 authentication complete!" << endl << endl;
        }
        else cout << endl << "Receive from V: " << buffer << endl;
    }
    else {
        cout << "No response or error receiving from Service Server." << endl;
    }

    // Đóng kết nối với Service Server
    closesocket(clientSocket);
    WSACleanup();

    return 0;
}

*/

