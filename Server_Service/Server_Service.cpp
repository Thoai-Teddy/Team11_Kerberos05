#include "../Utils/Utils.h"

const int BLOCK_SIZE = 16;

std::string timeToString(time_t t) {
    std::tm* tm_ptr = std::localtime(&t);
    char buffer[20];
    std::strftime(buffer, sizeof(buffer), "%Y/%m/%d %H:%M:%S", tm_ptr);
    return std::string(buffer);
}

string authenTicketAndTakeSessionKey(const string& encryptTicket, info& client, const string& iv, const string& priKeyV, ServiceTicket& ticket) {
    // Bước 1: Chuyển encryptTicket thành vector<unsigned char>
    vector<unsigned char> cipherBytes = hexStringToVector(encryptTicket);

    // Bước 2: Chuyển priKeyV và iv sang vector<unsigned char>
    vector<unsigned char> key(priKeyV.begin(), priKeyV.end());
    vector<unsigned char> ivBytes(iv.begin(), iv.end());

    // Bước 3: Giải mã AES-CBC
    vector<unsigned char> decryptedBytes = aes_cbc_decrypt(cipherBytes, key, ivBytes);

    // Bước 4: Bỏ padding để lấy chuỗi gốc
    string decryptedText = unpadString(decryptedBytes);

    cout << "DECRYPT TICKET V: " << decryptedText << endl << endl;

    // Bước 5: Parse ServiceTicket
    ticket = parseServiceTicket(decryptedText);

    cout << "IDC: " << ticket.clientID << endl
        << "ADC: " << ticket.clientAD << endl
        << "RealmC: " << ticket.realmc << endl;

    // Bước 6: Xác thực
    //Connect to DB SQL Server
    soci::session sql(soci::odbc,
        "Driver={ODBC Driver 17 for SQL Server};"
        "Server=DESKTOP-UE4ET37;"
        "Database=SERVERV;"
        "Uid=sa;"
        "Pwd=211038;"
        "TrustServerCertificate=Yes;"
        "Encrypt=Yes;");

    std::cout << "Kết nối thành công tới SERVERV!\n";

    std::string realm, address;

    // Truy vấn thông tin REALMC và ADC theo IDC
    soci::indicator indRealm, indAddress;
    soci::statement st = (sql.prepare <<
        "SELECT REALMC, ADC FROM dbo.Client WHERE IDC = :idc",
        soci::use(ticket.clientID), soci::into(realm, indRealm), soci::into(address, indAddress));

    // Kiểm tra kết quả và gán giá trị nếu hợp lệ
    st.execute();
    if (st.fetch() && indRealm == soci::i_ok && indAddress == soci::i_ok) {
        cout << "AD from DB: " << address << endl
            << "RealmC from DB: " << realm << endl << endl;
        client.setID(ticket.clientID);
        client.setAD(address);
        client.setRealm(realm);
    }

    if (client.getID() != "") {
        std::cout << "Tìm thấy client:\n";
        std::cout << "ID: " << client.getID() << "\n";
        std::cout << "ADC: " << client.getAD() << "\n";
        std::cout << "Realm: " << client.getRealm() << "\n\n";

        if (client.getAD() != ticket.clientAD) {
            cout << "Invalid ADC!" << endl << endl;
            return "mismatch!";
        }
        if (client.getRealm() != ticket.realmc) {
            cout << "Invalid RealmC!" << endl << endl;
            return "mismatch!";
        }
    }
    else return "mismatch!";

    time_t from = chrono::system_clock::to_time_t(ticket.timeInfo.from);
    time_t till = chrono::system_clock::to_time_t(ticket.timeInfo.till);
    time_t rtime = chrono::system_clock::to_time_t(ticket.timeInfo.rtime);
    time_t t_now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    std::cout << "Thời gian FROM  : " << std::put_time(std::localtime(&from), "%d/%m/%Y %H:%M:%S") << '\n';
    std::cout << "Thời gian TILL  : " << std::put_time(std::localtime(&till), "%d/%m/%Y %H:%M:%S") << '\n';
    std::cout << "Thời gian RTIME : " << std::put_time(std::localtime(&rtime), "%d/%m/%Y %H:%M:%S") << '\n';
    std::cout << "Thời gian NOW   : " << std::put_time(std::localtime(&t_now), "%d/%m/%Y %H:%M:%S") << '\n';

    string checkTime = check_ticket_time(to_string(from), to_string(till), to_string(rtime));
    if (checkTime == "VALID") {
        cout << endl << "Valid ticket date" << endl << endl;
    }
    if (checkTime == "INVALID" || checkTime == "RENEW") {
        cout << "Invalid ticket date!" << endl << endl;
        return "mismatch!";
    }

    return ticket.sessionKey;
}

string authenAuthenticatorAndGetSubkey(const string& encryptAuthenticator, ServiceServerData& service, const ServiceTicket ticket, info& client, const string& iv, const string& priKeyV) {
    vector<unsigned char> cipherBytes = hexStringToVector(encryptAuthenticator);
    vector<unsigned char> key_vec(priKeyV.begin(), priKeyV.end());
    vector<unsigned char> ivBytes(iv.begin(), iv.end());
    bool sucess = true;

    vector<unsigned char> decryptedBytes = aes_cbc_decrypt(cipherBytes, key_vec, ivBytes);

    string decryptedText = unpadString(decryptedBytes);

    AuthenticatorC auth = parseAuthenticator(decryptedText);


    if (auth.clientID != client.getID()) {
        sucess = false;
        cout << "Invalid IDC in Authen!" << endl << endl;
        return "mismatch!";
    }
    if (auth.realmc != client.getRealm()) {
        sucess = false;
        cout << "Invalid RealmC in Authen!" << endl << endl;
        return "mismatch!";
    }

    time_t from = chrono::system_clock::to_time_t(ticket.timeInfo.from);
    time_t till = chrono::system_clock::to_time_t(ticket.timeInfo.till);
    time_t ts2_time = std::chrono::system_clock::to_time_t(auth.TS2);

    std::string ts2_str = timeToString(ts2_time);
    std::string from_str = timeToString(from);
    std::string till_str = timeToString(till);
    std::cout << "Thời gian FROM  : " << from_str << '\n';
    std::cout << "Thời gian TILL  : " << till_str << '\n';
    std::cout << "Thời gian TS2  : " << ts2_str << '\n';

    if (ts2_time < from || ts2_time > till) {
        sucess = false;
        std::cerr << "[ERROR] TS2 invalid!\n";
        return "mismatch!";
    }
    else {
        std::cout << "[OK] TS2 valid.\n";
    }

    if (sucess) {
        service.TS2 = auth.TS2;
        service.seqNum = auth.seqNum;
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

    cout << endl << "Plaintext from V: " << oss.str() << endl;

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
string processServiceResponse(ServiceServerData& service, const string& decryptMessage, info& client, const string& ivTicket,
    const string& ivAuth, const string& priKeyV, string iv) {
    string cipherTicket, options, authen;
    string encryptMessage = "";
    ServiceTicket ticket;

    splitAndAssign(decryptMessage, options, cipherTicket, authen);

    string sessionKey = authenTicketAndTakeSessionKey(cipherTicket, client, ivTicket, priKeyV, ticket);
    if (sessionKey == "mismatch!") return "Invalid information in Ticket!";
    else {
        string subKey = authenAuthenticatorAndGetSubkey(authen, service, ticket, client, ivAuth, sessionKey);
        if (subKey == "mismatch!") return "Invalid information in Authenticator!";
        else if (!checkAPOptionsFromBitString(options)) {
            encryptMessage = "Kerberos 5 authentication complete!";
        }
        else {
            encryptMessage = encryptServerServiceData(service, subKey, iv, sessionKey) + "||" + iv;
        }
    }

    return encryptMessage;
}

int main() {
    WSADATA wsaData;
    SOCKET serviceSocket, clientSocket;
    sockaddr_in serviceAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[2048]; // Tăng kích thước nếu dữ liệu dài hơn
    string priKeyV = "ThereIsAManOnSky"; // Khóa bí mật của Service Server (16 bytes)
    string iv = generateRandomString();     // random IV để mã hóa phản hồi

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

    // Nhận tin nhắn chứa Ticket và Authenticator
    memset(buffer, 0, sizeof(buffer));
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) {
        cerr << "Error receiving data from client.\n";
        closesocket(clientSocket);
        closesocket(serviceSocket);
        WSACleanup();
        return 1;
    }

    string decryptMessage(buffer);
    cout << "Received encrypted service message: " << decryptMessage << "\n";

    //Tách iv 
    string ivAuth = "";  // IV để giải mã Authenticator
    try {
        ivAuth = extractAfterSecondDoublePipe(decryptMessage);
    }
    catch (const exception& ex) {
        cerr << "Error: " << ex.what() << endl << endl;
    }
    string ivTicket = ""; // IV để giải mã Ticket
    try {
        ivTicket = extractAfterFirstDoublePipe(decryptMessage);
    }
    catch (const exception& ex) {
        cerr << "Error: " << ex.what() << endl << endl;
    }

    // Tạo đối tượng giả định client info
    //info client("client123", "192.168.1.10", "REALM1", "", "");
    info client("", "", "", "", "");

    // Tạo dữ liệu dịch vụ
    ServiceServerData service;

    // Xử lý xác thực ticket + authenticator, tạo phản hồi
    string response = processServiceResponse(service, decryptMessage, client, ivTicket, ivAuth, priKeyV, iv);

    size_t pos = response.find('|');
    if (pos != std::string::npos) cout << endl << "Encrypt mess: " << response << endl << endl;
    else cout << endl << "Message to client: " << response << endl << endl;

    // Gửi phản hồi
    send(clientSocket, response.c_str(), response.length(), 0);

    // Đóng socket
    closesocket(clientSocket);
    closesocket(serviceSocket);
    WSACleanup();

    return 0;
}
