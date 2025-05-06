#include "../Utils/Utils.h"
const int BLOCK_SIZE = 16;

int main() {
    WSADATA wsaData;
    SOCKET asSocket, clientSocket;
    sockaddr_in asAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[1024];

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    asSocket = socket(AF_INET, SOCK_STREAM, 0);
    asAddr.sin_family = AF_INET;
    asAddr.sin_addr.s_addr = INADDR_ANY;
    asAddr.sin_port = htons(8800);

    bind(asSocket, (sockaddr*)&asAddr, sizeof(asAddr));
    listen(asSocket, 5);

    cout << "AS Server listening on port 8800..." << endl;

    clientSocket = accept(asSocket, (sockaddr*)&clientAddr, &clientAddrLen);
    cout << "Client connected to AS." << endl << endl;

    info server("IDServerAS", "RealmServerAS");


    // Nhận request từ client
    std::string client_request = receive_message(clientSocket);
    cout << "Client request: " << client_request << endl << endl;

    // Tách dữ liệu từ client gửi đến
    std::vector <std::string> client_request_vector = splitString(client_request, "|");
    if (client_request_vector.size() < 8) {
        throw std::runtime_error("Invalid authentication request format");
    }

    std::string options_from_client = client_request_vector[0];
    std::string id_c_from_client = client_request_vector[1];
    std::string realm_c_from_client = client_request_vector[2];
    std::string id_tgs_from_client = client_request_vector[3];
    std::string times_from_from_client = client_request_vector[4];
    std::string times_till_from_client = client_request_vector[5];
    std::string times_rtime_from_client = client_request_vector[6];
    std::string nonce1_from_client = client_request_vector[7];

    info client(id_c_from_client, realm_c_from_client);

    std::string now = get_current_time_formatted();
    if (now < times_from_from_client || now > times_till_from_client)
    {
        string error = "Cannot create TGS ticket!Ticket has expired!";
        cout << error << endl << endl;
        send_message(clientSocket, error);
    }

    // Sinh khóa K_c,tgs, hiện tại đang để mặc định
    std::string K_c_tgs = "HelloNiceToMeetU";

    // Kiểm tra ID_tgs trong database, lấy Ktgs và Reamltgs, hiện tại đang để mặc định
    info TGS("IDServerTGS", "RealmServerTGS");
    std::string K_tgs = "ScoobydooWhereRU";
    TGS.setPrivateKey(K_tgs);

    if (K_tgs.size() > BLOCK_SIZE) {
        K_tgs = K_tgs.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> key_tgs(K_tgs.begin(), K_tgs.end());
    while (key_tgs.size() < BLOCK_SIZE) key_tgs.push_back(0x00);

    // Tạo iv để mã hóa TGS ticket
    string iv_pre_tgs_ticket = "WelcomeToOurHome";
    if (iv_pre_tgs_ticket.size() > BLOCK_SIZE) {
        iv_pre_tgs_ticket = iv_pre_tgs_ticket.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> iv_tgs_ticket(iv_pre_tgs_ticket.begin(), iv_pre_tgs_ticket.end());
    while (iv_tgs_ticket.size() < BLOCK_SIZE) iv_tgs_ticket.push_back(0x00); // Bổ sung nếu thiếu

    // Lấy client_key từ database, hiện tại đang để mặc định
    std::string K_c = "TonightIWillSing";
    client.setPrivateKey(K_c);


    if (K_c.size() > BLOCK_SIZE) {
        K_c = K_c.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> key_client(K_c.begin(), K_c.end());
    while (key_client.size() < BLOCK_SIZE) key_client.push_back(0x00); // Bổ sung nếu thiếu

    // Tạo iv để mã hóa với K_c
    string iv_pre = "ThisIsMyIVForEnc";
    if (iv_pre.size() > BLOCK_SIZE) {
        iv_pre = iv_pre.substr(0, BLOCK_SIZE);
    }
    vector<unsigned char> iv(iv_pre.begin(), iv_pre.end());
    while (iv.size() < BLOCK_SIZE) iv.push_back(0x00); // Bổ sung nếu thiếu

    // Tạo ticket TGS đã mã hóa để gửi lại cho client
    Ticket TGS_ticket;
    TGS_ticket.flags = options_from_client;
    TGS_ticket.sessionKey = K_c_tgs;
    TGS_ticket.realmc = client.getRealm();
    TGS_ticket.clientID = client.getID();
    TGS_ticket.clientAD = "192.168.2.5";
    //TGS_ticket.clientAD = client.getAD();

    TGS_ticket.times_from = times_from_from_client;
    TGS_ticket.times_till = times_till_from_client;
    TGS_ticket.times_rtime = times_rtime_from_client;

	std::string TGS_ticket_plaintext = TGS_ticket.flags + "|" + TGS_ticket.sessionKey + "|" + TGS_ticket.realmc + "|" + TGS_ticket.clientID + "|"
        + TGS_ticket.clientAD + "|" + TGS_ticket.times_from + "|" + TGS_ticket.times_till + "|" + TGS_ticket.times_rtime;
    
    
    std::string plaintext = K_c_tgs + "|" + times_from_from_client + "|" + times_till_from_client + "|" + times_rtime_from_client + "|" 
        + nonce1_from_client + "|" + TGS.getRealm() + "|" + TGS.getID();
    
    // Padding plaintext
    vector<unsigned char> padded_TGS_ticket_plaintext = padString(TGS_ticket_plaintext);
    vector<unsigned char> padded_plaintext = padString(plaintext);

    // Mã hóa
    vector<unsigned char> TGS_ticket_encrypted = aes_cbc_encrypt(padded_TGS_ticket_plaintext, key_tgs, iv_tgs_ticket);
    string TGS_ticket_encrypted_str = bytesToHex(TGS_ticket_encrypted);

    vector<unsigned char> ciphertext = aes_cbc_encrypt(padded_plaintext, key_client, iv);
    string ciphertext_str = bytesToHex(ciphertext);

    cout << "Ciphertext (encrypted by K_c): " << ciphertext_str << endl << endl;

    cout << "TGS Ticket (encrypted by K_c): " << TGS_ticket_encrypted_str << endl << endl;

    vector<unsigned char> plaintext_block_from_as = aes_cbc_decrypt( TGS_ticket_encrypted, key_tgs, iv_tgs_ticket);


    string plaintext_from_as = unpadString(plaintext_block_from_as);
    cout << "Plaintext after decrypted with K_c_tgs: " << plaintext_from_as << endl << endl;


    // Gửi dữ liệu về cho client
    string response = client.getRealm() + "|" + client.getID() + "|" + TGS_ticket_encrypted_str + "|" + ciphertext_str;
    cout << "Response from server: " << response << endl << endl;
    send_message(clientSocket, response);

    closesocket(clientSocket);
    closesocket(asSocket);
    WSACleanup();
    return 0;
}

