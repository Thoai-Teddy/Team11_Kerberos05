#include "../Utils/Utils.h"
const int BLOCK_SIZE = 16;

std::chrono::system_clock::time_point parse_time(const std::string& time_str) {
    std::tm tm = {};
    std::istringstream ss(time_str);
    ss >> std::get_time(&tm, "%Y%m%d%H%M%S");

    if (ss.fail()) {
        throw std::runtime_error("Failed to parse time string: " + time_str);
    }

    // mktime assumes tm is in local time; if you want UTC, use timegm() if available
    std::time_t time = std::mktime(&tm);

    // Nếu đang dùng GMT/UTC thì thay mktime bằng timegm nếu platform hỗ trợ
    return std::chrono::system_clock::from_time_t(time);
}

uint64_t time_point_to_uint64(const std::chrono::system_clock::time_point& tp) {
    return static_cast<uint64_t>(std::chrono::system_clock::to_time_t(tp));
}
/*
std::string timeTostring(std::chrono::system_clock::time_point timePoint) {
    std::time_t timeT = std::chrono::system_clock::to_time_t(timePoint);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&timeT), "%a %b %d %H:%M:%S %Y");
    return oss.str();  // Không có \n
}
*/

std::string timeTostring(std::chrono::system_clock::time_point timePoint) {
    std::time_t timeT = std::chrono::system_clock::to_time_t(timePoint);
    return std::to_string(timeT);
}

string decryptTicketV(const string& encryptTicket, const string& iv, const string& priKeyV) {
    string response = "renew";

    // Bước 1: Chuyển encryptTicket thành vector<unsigned char>
    vector<unsigned char> cipherBytes = hexStringToVector(encryptTicket);

    // Bước 2: Chuyển priKeyV và iv sang vector<unsigned char>
    vector<unsigned char> key(priKeyV.begin(), priKeyV.end());
    vector<unsigned char> ivBytes(iv.begin(), iv.end());

    // Bước 3: Giải mã AES-CBC
    vector<unsigned char> decryptedBytes = aes_cbc_decrypt(cipherBytes, key, ivBytes);

    // Bước 4: Bỏ padding để lấy chuỗi gốc
    string decryptedText = unpadString(decryptedBytes);

    cout << endl << "[DECRYPT]\n[EXPIRED TICKET V]: " << decryptedText << endl << endl;

    // Bước 5: Parse ServiceTicket
    ServiceTicket ticket = parseServiceTicket(decryptedText);
    if (!hasRenewableFlag(ticket.flags)) {
        response = "This ticket can not renewable!";
        cout << endl << "[ALERT]\n" << response << endl << endl;
    }
    return response;
}

string decryptAuthenticatorc(const string& Mess, const string& Kc_tgs, const string& iv_authen) {
    vector<unsigned char> cipherBytes = hexStringToVector(Mess);
    vector<unsigned char> key(Kc_tgs.begin(), Kc_tgs.end());
    vector<unsigned char> ivBytes(iv_authen.begin(), iv_authen.end());

    vector<unsigned char> decryptedBytes = aes_cbc_decrypt(cipherBytes, key, ivBytes);

    string decryptedText = unpadString(decryptedBytes);

    return decryptedText;
}

using namespace std;

int main() {
    WSADATA wsaData;
    SOCKET tgsSocket, clientSocket;
    sockaddr_in tgsAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[1024];

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    tgsSocket = socket(AF_INET, SOCK_STREAM, 0);
    tgsAddr.sin_family = AF_INET;
    tgsAddr.sin_addr.s_addr = INADDR_ANY;
    tgsAddr.sin_port = htons(8801);

    bind(tgsSocket, (sockaddr*)&tgsAddr, sizeof(tgsAddr));
    listen(tgsSocket, 5);

    cout << "TGS Server listening on port 8801...\n";

    clientSocket = accept(tgsSocket, (sockaddr*)&clientAddr, &clientAddrLen);
    cout << "Client connected to TGS.\n";

    //Mặc định Key
    std::string K_tgs = "ScoobydooWhereRU";
    std::string K_v = "ThereIsAManOnSky";
    std::string K_c_v = "YouAreVeryPretty";

    //Cấu hình ServerService
    info ServerV("IDServerV", "RealmServerV");

    int count = 0;

    do {
        // Nhận dữ liệu từ Client
        // Đặt timeout cho socket - 5 phút (300 giây)
        struct timeval timeout;
        timeout.tv_sec = 300;   // 300 giây = 5 phút
        timeout.tv_usec = 0;    // microseconds

        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

        // Nhận dữ liệu từ Client
        memset(buffer, 0, sizeof(buffer));
        int recvResult = recv(clientSocket, buffer, sizeof(buffer), 0);

        if (recvResult == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                std::cerr << "Timeout: Do not receive data from client in 5 minutes!" << std::endl;
            }
            else {
                std::cerr << "Recv error: " << err << std::endl;
            }
            closesocket(clientSocket);
            WSACleanup();
            return -1;
        }
        else if (recvResult == 0) {
            std::cerr << "Connection is closed by client!" << std::endl;
            closesocket(clientSocket);
            WSACleanup();
            return -1;
        }
        else {
            std::cout << "[Client -> TGS]: " << buffer << std::endl << endl;
        }

        // Lấy iv để giải mã TGS ticket
        string txt(buffer);
        string iv_pre_tgs_ticket = "";
        try {
            iv_pre_tgs_ticket = extractAfterFirstDoublePipe(txt);
        }
        catch (const exception& ex) {
            cerr << "Error: " << ex.what() << endl << endl;
        }

        if (iv_pre_tgs_ticket.size() > BLOCK_SIZE) {
            iv_pre_tgs_ticket = iv_pre_tgs_ticket.substr(0, BLOCK_SIZE);
        }
        vector<unsigned char> iv_tgs_ticket(iv_pre_tgs_ticket.begin(), iv_pre_tgs_ticket.end());

        while (iv_tgs_ticket.size() < BLOCK_SIZE) iv_tgs_ticket.push_back(0x00); // Bổ sung nếu thiếu

        // Tách iv để giải mã authenticatorc
        string iv_authen = "";
        try {
            iv_authen = extractAfterSecondDoublePipe(txt);
        }
        catch (const exception& ex) {
            cerr << "Error: " << ex.what() << endl << endl;
        }

        if (iv_authen.size() > BLOCK_SIZE) {
            iv_authen = iv_authen.substr(0, BLOCK_SIZE);
        }
        vector<unsigned char> iv_a(iv_authen.begin(), iv_authen.end());

        std::string options_from_client, ticket_v_from_client, iv_v_from_client;

        extractOptionAndTicket(txt, options_from_client, ticket_v_from_client, iv_v_from_client);

        if (!ticket_v_from_client.empty()) {
            cout << endl << "[EXPIRED TICKET V]: " << ticket_v_from_client << endl;
        }
        
        if (count != 0 && !isRenewOption(options_from_client)) {
            string response = "You have been issued a ticket!";
            cout << "[ALERT]\n[TGS -> Client]: " << response << endl << endl;
            send_message(clientSocket, response);
            break;
        }
        if (isRenewOption(options_from_client) && !ticket_v_from_client.empty()) {  //giải mã ticketv và kiểm tra flag
            string response = decryptTicketV(ticket_v_from_client, iv_v_from_client, K_v);
            if(response != "renew") send_message(clientSocket, response);
        };

        while (iv_a.size() < BLOCK_SIZE) iv_a.push_back(0x00); // Bổ sung nếu thiếu
        std::vector <std::string> client_request_vector = splitString(txt, "|");
        std::string id_v_from_client = client_request_vector[0];
        std::string times_from_from_client = client_request_vector[1];
        std::string times_till_from_client = client_request_vector[2];
        std::string times_rtime_from_client = client_request_vector[3];
        std::string nonce2_from_client = client_request_vector[4];
        std::string ticket_tgs_from_client = client_request_vector[5];

        std::string authenticatorc_from_client;
        for (size_t i = 6; i < client_request_vector.size(); ++i) {
            if (i > 6) authenticatorc_from_client += "|";  // thêm dấu phân cách
            authenticatorc_from_client += client_request_vector[i];
            //cout << endl << "Authen: " << authenticatorc_from_client << endl << endl;
        }
        cout << endl << "Received Authenticatorc: " << authenticatorc_from_client << endl << endl;



        std::string now = get_current_time_formatted();
        if (now > times_rtime_from_client)
        {
            string error = "Cannot create V ticket! Ticket has expired!";
            cout << error << endl << endl;
            send_message(clientSocket, error);
        }

        cout << "Received Ticket TGS: " << ticket_tgs_from_client << "\n\n";

        //Giải mã Ticket TGS
        std::vector<unsigned char>  ticket_tgs_from_client_vector = hexStringToVector(ticket_tgs_from_client);
        K_tgs = "secretkeytgservr";
        if (K_tgs.size() > BLOCK_SIZE) {
            K_tgs = K_tgs.substr(0, BLOCK_SIZE);
        }
        vector<unsigned char> key_tgs(K_tgs.begin(), K_tgs.end());
        while (key_tgs.size() < BLOCK_SIZE) key_tgs.push_back(0x00); // Bổ sung nếu thiếu

        vector<unsigned char> plaintext_block_from_as = aes_cbc_decrypt(ticket_tgs_from_client_vector, key_tgs, iv_tgs_ticket);

        string plaintext_from_as = unpadString(plaintext_block_from_as);

        cout << "[DECRYPT]\n[TGT]: " << plaintext_from_as << endl << endl;

        vector <std::string> parts_plaintext_from_as = splitString(plaintext_from_as, "|");

        Ticket TGS_ticket;
        TGS_ticket.flags = parts_plaintext_from_as[0];
        TGS_ticket.sessionKey = parts_plaintext_from_as[1];
        TGS_ticket.realmc = parts_plaintext_from_as[2];
        TGS_ticket.clientID = parts_plaintext_from_as[3];
        TGS_ticket.clientAD = parts_plaintext_from_as[4];
        TGS_ticket.times_from = parts_plaintext_from_as[5];
        TGS_ticket.times_till = parts_plaintext_from_as[6];
        TGS_ticket.times_rtime = parts_plaintext_from_as[7];

        std::string authenticatorc_decrypt = decryptAuthenticatorc(authenticatorc_from_client, TGS_ticket.sessionKey, iv_authen);

        cout << "[DECRYPT]\n[Authenticatorc]: " << authenticatorc_decrypt << "\n";

        AuthenticatorC authenticator_de = parseAuthenticator(authenticatorc_decrypt);


        //Kiểm tra
        if (TGS_ticket.clientID != authenticator_de.clientID) {
            // Sai client → từ chối
            throw std::runtime_error("Client ID mismatch between TicketTGS and AuthenticatorC");
        }
        else {
            cout << "Client ID match between TicketTGS and AuthenticatorC" << endl;
        }
        if (TGS_ticket.realmc != authenticator_de.realmc) {
            // Sai realm → từ chối
            throw std::runtime_error("Realm mismatch between TicketTGS and AuthenticatorC");
        }
        else {
            cout << "Realm match between TicketTGS and AuthenticatorC" << endl;
        }


        //Mã hóa
        uint32_t flag;
        flag = RENEWABLE;
        ServiceTicket Ticket_V;
        Ticket_V.flags = apOptionsToBitString(flag);
        Ticket_V.sessionKey = K_c_v;
        Ticket_V.realmc = TGS_ticket.realmc;
        Ticket_V.clientID = TGS_ticket.clientID;
        Ticket_V.clientAD = TGS_ticket.clientAD;
        if (count == 0) {
            Ticket_V.timeInfo.from = std::chrono::system_clock::now() - std::chrono::hours(9);
            Ticket_V.timeInfo.till = Ticket_V.timeInfo.from + std::chrono::hours(8);
            Ticket_V.timeInfo.rtime = Ticket_V.timeInfo.till + std::chrono::hours(24);
        }
        else {
            Ticket_V.timeInfo.from = std::chrono::system_clock::now();
            Ticket_V.timeInfo.till = Ticket_V.timeInfo.from + std::chrono::hours(8);
            Ticket_V.timeInfo.rtime = Ticket_V.timeInfo.till + std::chrono::hours(24);
        }

        std::string Ticket_V_plaintext = buildServiceTicketPlaintext(Ticket_V.flags, Ticket_V.sessionKey, Ticket_V.realmc, Ticket_V.clientID, Ticket_V.clientAD,
            time_point_to_uint64(Ticket_V.timeInfo.from), time_point_to_uint64(Ticket_V.timeInfo.till), time_point_to_uint64(Ticket_V.timeInfo.rtime));

        std::string plaintext = K_c_v + "|" + timeTostring(Ticket_V.timeInfo.from) + "|" + timeTostring(Ticket_V.timeInfo.till) + "|" + timeTostring(Ticket_V.timeInfo.rtime) + "|"
            + nonce2_from_client + "|" + ServerV.getRealm() + "|" + ServerV.getID();

        std::cout << plaintext << std::endl;



        // Padding plaintext
        cout << endl << "TICKET V:" << Ticket_V_plaintext << endl << endl;
        vector<unsigned char> padded_Ticket_V_plaintext = padString(Ticket_V_plaintext);
        vector<unsigned char> padded_plaintext = padString(plaintext);

        // Mã hóa Ticket V

        if (K_v.size() > BLOCK_SIZE) {
            K_v = K_v.substr(0, BLOCK_SIZE);
        }
        vector<unsigned char> Key_v(K_v.begin(), K_v.end());

        while (Key_v.size() < BLOCK_SIZE) Key_v.push_back(0x00); // Bổ sung nếu thiếu

        // Tạo iv để mã hóa Ticket V
        string iv_pre_v_ticket = "";
        iv_pre_v_ticket = generateRandomString();
        if (iv_pre_v_ticket.size() > BLOCK_SIZE) {
            iv_pre_v_ticket = iv_pre_v_ticket.substr(0, BLOCK_SIZE);
        }
        vector<unsigned char> iv_v_ticket(iv_pre_v_ticket.begin(), iv_pre_v_ticket.end());

        while (iv_v_ticket.size() < BLOCK_SIZE) iv_v_ticket.push_back(0x00); // Bổ sung nếu thiếu

        vector<unsigned char> Ticket_V_encrypted = aes_cbc_encrypt(padded_Ticket_V_plaintext, Key_v, iv_v_ticket);
        string  Ticket_V_encrypted_str = bytesToHex(Ticket_V_encrypted);

        cout << "[ENCRYPT]\n[Ticket V]: " << Ticket_V_encrypted_str << endl << endl;

        vector<unsigned char> cipherBytes = hexStringToVector(Ticket_V_encrypted_str);
        vector<unsigned char> key(K_v.begin(), K_v.end());
        vector<unsigned char> ivBytes(iv_pre_v_ticket.begin(), iv_pre_v_ticket.end());
        vector<unsigned char> decryptedBytes = aes_cbc_decrypt(cipherBytes, key, ivBytes);
        string decryptedText = unpadString(decryptedBytes);

        // Mã hóa plaintext
        std::string K_c_tgs = TGS_ticket.sessionKey;
        if (K_c_tgs.size() > BLOCK_SIZE) {
            K_c_tgs = K_c_tgs.substr(0, BLOCK_SIZE);
        }
        vector<unsigned char> Key_c_tgs(K_c_tgs.begin(), K_c_tgs.end());

        while (Key_c_tgs.size() < BLOCK_SIZE) Key_c_tgs.push_back(0x00); // Bổ sung nếu thiếu

        // Tạo iv để mã hóa plaintext
        string iv_pre_v = generateRandomString();
        if (iv_pre_v.size() > BLOCK_SIZE) {
            iv_pre_v = iv_pre_v.substr(0, BLOCK_SIZE);
        }
        vector<unsigned char> iv_v(iv_pre_v.begin(), iv_pre_v.end());

        while (iv_v.size() < BLOCK_SIZE) iv_v.push_back(0x00); // Bổ sung nếu thiếu

        vector<unsigned char> ciphertext = aes_cbc_encrypt(padded_plaintext, Key_c_tgs, iv_v);
        string ciphertext_str = bytesToHex(ciphertext);

        cout << "[ENCRYPT]\n[Message to Client]: " << ciphertext_str << endl << endl;


        // Gửi dữ liệu về cho client
        string response = Ticket_V.realmc + "|" + Ticket_V.clientID + "|" + Ticket_V_encrypted_str + "||" + iv_pre_v_ticket + "|" + ciphertext_str + "||" + iv_pre_v;
        cout << "[TGS -> Client]: " << response << endl << endl;
        send_message(clientSocket, response);

        // Gửi Service Ticket
        string serviceTicket = "ServiceTicket_for_" + string(buffer);
        send(clientSocket, serviceTicket.c_str(), serviceTicket.length(), 0);
        count++;
    } while (true);

    closesocket(clientSocket);
    closesocket(tgsSocket);
    WSACleanup();
    return 0;
}
