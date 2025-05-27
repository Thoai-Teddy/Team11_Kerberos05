#include "../Utils/Utils.h"
const int BLOCK_SIZE = 16;

int main() {
    WSADATA wsaData;
    SOCKET asSocket, clientSocket;
    sockaddr_in asAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);

    // Khởi tạo Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cout << "WSAStartup failed!" << std::endl;
        return 1;
    }

    // Tạo socket
    asSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (asSocket == INVALID_SOCKET) {
        std::cout << "Socket creation failed!" << std::endl;
        WSACleanup();
        return 1;
    }

    asAddr.sin_family = AF_INET;
    asAddr.sin_addr.s_addr = INADDR_ANY;
    asAddr.sin_port = htons(8800);

    // Gán socket
    if (bind(asSocket, (sockaddr*)&asAddr, sizeof(asAddr)) == SOCKET_ERROR) {
        std::cout << "Bind failed!" << std::endl;
        closesocket(asSocket);
        WSACleanup();
        return 1;
    }

    listen(asSocket, 5);
    std::cout << "AS Server listening on port 8800..." << std::endl;

    // Kết nối database
    soci::session sql(soci::odbc,
        "Driver={SQL Server};Server=ADMIN-PC\\SQLSERVER;Database=KDC;Trusted_Connection=Yes;");
    std::cout << "Connect to database successfully." << std::endl;

    std::cout << std::endl << "================ Cho client ket noi ================" << std::endl;
    std::cout << "Waiting for client connection..." << std::endl;
    clientSocket = accept(asSocket, (sockaddr*)&clientAddr, &clientAddrLen);
    if (clientSocket == INVALID_SOCKET) {
        std::cout << "Error: Accept failed!" << std::endl;
        //continue;
        closesocket(clientSocket);

        closesocket(asSocket);
        WSACleanup();
        return -1;
    }
    std::cout << "Client connected." << std::endl;


    //================ Dang nhap ================
    std::cout << std::endl << "================ Dang nhap ================" << std::endl;
    std::string login_username;
    try {
        login_username = receive_message(clientSocket);
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        closesocket(clientSocket);
        closesocket(asSocket);
        WSACleanup();
        //return -1;
        exit(-1);
    }
    std::cout << "[LOGIN]\n[Client -> AS]: " << login_username << std::endl;

    // Truy vấn password từ database
    std::string hashed_pass_db;
    soci::indicator ind_hashed_pass;

    soci::statement st_hashed_pass = (sql.prepare <<
        "SELECT HASHEDPASS FROM Client WHERE IDC = :idc",
        soci::use(login_username), soci::into(hashed_pass_db, ind_hashed_pass));

    st_hashed_pass.execute();
    if (st_hashed_pass.fetch() == false || ind_hashed_pass != soci::i_ok)
    {
        std::cout << "Error: Invalid username!" << std::endl;
        send_message(clientSocket, "INVALID USERNAME!");
        closesocket(clientSocket);
        closesocket(asSocket);
        WSACleanup();
        //return -1;
        exit(-1);
    }

    // Chuyển password từ chữ in hoa về chữ thường
    transform(hashed_pass_db.begin(), hashed_pass_db.end(), hashed_pass_db.begin(), ::tolower);

    // Lấy key mã hóa là 16 bytes đầu của hashed password
    std::string key_client = hashed_pass_db;
    if (key_client.size() > BLOCK_SIZE) {
        key_client = key_client.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> key_client_vec(key_client.begin(), key_client.end());
    while (key_client_vec.size() < BLOCK_SIZE) key_client_vec.push_back(0x00); // Bổ sung nếu thiếu

    // Tạo iv để mã hóa với key_client
    std::string iv_log_in = generateRandomString(BLOCK_SIZE);
    vector<unsigned char> iv_log_in_vec(iv_log_in.begin(), iv_log_in.end());
    while (iv_log_in_vec.size() < BLOCK_SIZE) iv_log_in_vec.push_back(0x00); // Bổ sung nếu thiếu

    // Padding username - plaintext
    vector<unsigned char> padded_username = padString(login_username);

    // Mã hóa username
    vector<unsigned char> username_encrypted = aes_cbc_encrypt(padded_username, key_client_vec, iv_log_in_vec);
    std::string username_encrypted_str = bytesToHex(username_encrypted);

    std::string log_in_response = username_encrypted_str + "|" + iv_log_in;

    std::cout << "[AS -> Client]: " << log_in_response << std::endl;

    send_message(clientSocket, log_in_response);

    //======= Bước 1: Nhận yêu cầu xin cấp vé TGT của Client ======

    // Nhận yêu cầu ticket TGS từ client
    std::string ticket_request;
    try {
        ticket_request = receive_message(clientSocket);
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        closesocket(clientSocket);
        closesocket(asSocket);
        WSACleanup();
        //return -1;
        exit(-1);
    }

    if (ticket_request == "WRONG PASSWORD!") {
        std::cout << "LOG IN FAILED! WRONG PASSWORD!" << std::endl;
        closesocket(clientSocket);
        closesocket(asSocket);
        WSACleanup();
        //return -1;
        exit(-1);
    }

    std::cout << std::endl << "======= Buoc 1: Nhan yeu cau xin cap ve TGT cua Client ======" << std::endl;
    std::cout << "[Client -> AS]: " << ticket_request << std::endl;

    std::vector<std::string> ticket_parts = splitString(ticket_request, "|");
    if (ticket_parts.size() < 8) {
        send_message(clientSocket, "INVALID TICKET REQUEST FORMAT!");
        closesocket(clientSocket);
        closesocket(asSocket);
        WSACleanup();
        //return -1;
        exit(-1);
    }

    std::string options = ticket_parts[0];
    std::string idc = ticket_parts[1];
    std::string realmc = ticket_parts[2];
    std::string idtgs = ticket_parts[3];
    std::string t_from = ticket_parts[4];
    std::string t_till = ticket_parts[5];
    std::string t_rtime = ticket_parts[6];
    std::string nonce1 = ticket_parts[7];

    if (idc != login_username) {
        std::cout << "Error: Client haven't log in!" << std::endl;
        send_message(clientSocket, "WRONG ID!");
        closesocket(clientSocket);
        closesocket(asSocket);
        WSACleanup();
        //return -1;
        exit(-1);
    }

    // Lấy ADC của client từ database 
    std::string adc;
    soci::indicator ind_adc;

    soci::statement st_adc = (sql.prepare <<
        "SELECT ADC FROM Client WHERE IDC = :idc",
        soci::use(idc), soci::into(adc, ind_adc));

    st_adc.execute();
    if (st_adc.fetch() == FALSE || ind_adc != soci::i_ok) {
        std::cout << "Error: Query adc in database failed!" << std::endl;
        send_message(clientSocket, "QUERY ADC FAILED!");
        closesocket(clientSocket);
        closesocket(asSocket);
        WSACleanup();
        //return -1;
        exit(-1);
    }

    // Khóa bí mật K_c là key_client lấy từ 16 bytes đầu tiên của client password lưu trong database
    info client(idc, realmc, adc, "", key_client);

    std::string time_check = check_ticket_time(t_from, t_till, t_rtime);
    if (time_check == "INVALID") {
        std::cout << "Error: Cannot create TGS ticket! Ticket has expired!" << std::endl;
        send_message(clientSocket, "TICKET EXPIRED!");
        closesocket(clientSocket);        
        closesocket(asSocket);
        WSACleanup();
        //return -1;
        exit(-1);
    }

    std::cout << "Ticket time is valid." << std::endl;

    //======= Bước 2: Mã hóa TGS Ticket và thông điệp gửi về cho Client ======
    std::cout << std::endl << "======= Buoc 2: Ma hoa TGS Ticket va thong diep gui ve cho Client ======" << std::endl;

    // Kiểm tra ID_tgs trong database, lấy Ktgs và Reamltgs
    std::string ktgs, realmtgs;
    soci::indicator ind_ktgs, ind_realmtgs;

    soci::statement st_tgs = (sql.prepare <<
        "SELECT CONVERT(VARCHAR(MAX), KTGS), REALMTGS FROM TGSERVER WHERE IDTGS = :id",
        soci::use(idtgs), soci::into(ktgs, ind_ktgs), soci::into(realmtgs, ind_realmtgs));

    st_tgs.execute();
    if (st_tgs.fetch() == false || ind_ktgs != soci::i_ok || ind_realmtgs != soci::i_ok)
    {
        std::cout << "Error: ID_tgs is wrong!" << std::endl;
        send_message(clientSocket, "ID TGS WRONG!");
        closesocket(clientSocket);
        closesocket(asSocket);
        WSACleanup();
       // return -1;
        exit(-1);
    }

    std::cout << "Realm_tgs from database: " << realmtgs << std::endl;

    info TGS(idtgs, "", realmtgs, "", ktgs);

    // Tạo vector của khóa Ktgs
    if (ktgs.size() > BLOCK_SIZE) {
        ktgs = ktgs.substr(0, BLOCK_SIZE);
    }
    
    vector<unsigned char> K_tgs_vec(ktgs.begin(), ktgs.end());
    while (K_tgs_vec.size() < BLOCK_SIZE) K_tgs_vec.push_back(0x00);

    // Sinh khóa K_c,tgs ngẫu nhiên
    std::string K_c_tgs = generateRandomString(BLOCK_SIZE);
    std::cout << "Random K_c_tgs: " << K_c_tgs << std::endl;

    // Tạo iv để mã hóa TGS ticket
    string iv_pre_tgs_ticket = generateRandomString(BLOCK_SIZE);

    if (iv_pre_tgs_ticket.size() > BLOCK_SIZE) {
        iv_pre_tgs_ticket = iv_pre_tgs_ticket.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> iv_tgs_ticket(iv_pre_tgs_ticket.begin(), iv_pre_tgs_ticket.end());
    while (iv_tgs_ticket.size() < BLOCK_SIZE) iv_tgs_ticket.push_back(0x00); // Bổ sung nếu thiếu

    // Tạo iv để mã hóa với K_c
    string iv_pre = generateRandomString(BLOCK_SIZE);

    if (iv_pre.size() > BLOCK_SIZE) {
        iv_pre = iv_pre.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> iv(iv_pre.begin(), iv_pre.end());
    while (iv.size() < BLOCK_SIZE) iv.push_back(0x00); // Bổ sung nếu thiếu

    // Tạo ticket TGS
    Ticket TGS_ticket;
    TGS_ticket.flags = options;
    TGS_ticket.sessionKey = K_c_tgs;
    TGS_ticket.realmc = client.getRealm();
    TGS_ticket.clientID = client.getID();
    TGS_ticket.clientAD = client.getAD();
    TGS_ticket.times_from = t_from;
    TGS_ticket.times_till = t_till;
    TGS_ticket.times_rtime = t_rtime;

    std::string TGS_ticket_plaintext = TGS_ticket.flags + "|" + TGS_ticket.sessionKey + "|" + TGS_ticket.realmc + "|" + TGS_ticket.clientID + "|"
        + TGS_ticket.clientAD + "|" + TGS_ticket.times_from + "|" + TGS_ticket.times_till + "|" + TGS_ticket.times_rtime;

    std::cout << endl << "[TGT]: " << TGS_ticket_plaintext << std::endl << std::endl;

    // Tạo plaintext mã hóa bằng K_c
    std::string plaintext = K_c_tgs + "|" + t_from + "|" + t_till + "|" + t_rtime + "|"
        + nonce1 + "|" + TGS.getRealm() + "|" + TGS.getID();
    std::cout << "[Message to Client]: " << plaintext << std::endl << std::endl;

    // Padding plaintext
    vector<unsigned char> padded_TGS_ticket_plaintext = padString(TGS_ticket_plaintext);
    vector<unsigned char> padded_plaintext = padString(plaintext);

    // Mã hóa
    vector<unsigned char> TGS_ticket_encrypted = aes_cbc_encrypt(padded_TGS_ticket_plaintext, K_tgs_vec, iv_tgs_ticket);
    string TGS_ticket_encrypted_str = bytesToHex(TGS_ticket_encrypted);
    std::cout << "[ENCRYPT]\n[TGT]: " << TGS_ticket_encrypted_str << std::endl << std::endl;

    vector<unsigned char> ciphertext = aes_cbc_encrypt(padded_plaintext, key_client_vec, iv);
    string ciphertext_str = bytesToHex(ciphertext);
    std::cout << "[ENCRYPT]\n[MESSAGE]" << ciphertext_str << std::endl << std::endl;

    // Gửi dữ liệu về cho client
    string response = client.getRealm() + "|" + client.getID() + "|" + TGS_ticket_encrypted_str + "|" + iv_pre_tgs_ticket + "|" + ciphertext_str + "|" + iv_pre;
    std::cout << "[AS -> Client]: " << response << std::endl << std::endl << std::endl;
    send_message(clientSocket, response);

    closesocket(clientSocket);
    closesocket(asSocket);
    WSACleanup();
    //return 0;
    exit(0);
}
