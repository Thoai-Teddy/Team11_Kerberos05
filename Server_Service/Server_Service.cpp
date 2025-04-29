#include "../Utils/Utils.h"

string authenTicketAndTakeSessionKey(const string& encryptTicket, const info& client, const string& iv, const string& priKeyV) {
    // Bước 1: Chuyển encryptTicket thành vector<unsigned char>
    vector<unsigned char> cipherBytes(encryptTicket.begin(), encryptTicket.end());

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
        throw runtime_error("Client Address mismatch!");
    }
    if (ticket.realmc != client.getRealm()) {
        throw runtime_error("Realm mismatch!");
    }

    auto now = chrono::system_clock::now();
    if (now < ticket.timeInfo.from || now > ticket.timeInfo.till) {
        throw runtime_error("Ticket expired or not yet valid!");
    }

    // Bước 7: Trả về sessionKey
    return ticket.sessionKey;
}

//string authenAuthenticatorAndGetSubkey(const string& encryptAuthenticator, const info& client, const string& iv, const string& priKeyV) {
//    // Bước 1: Chuyển encryptAuthenticator thành vector<unsigned char>
//    vector<unsigned char> cipherBytes(encryptAuthenticator.begin(), encryptAuthenticator.end());
//
//    // Bước 2: Chuyển priKeyV và iv sang vector<unsigned char>
//    vector<unsigned char> key(priKeyV.begin(), priKeyV.end());
//    vector<unsigned char> ivBytes(iv.begin(), iv.end());
//
//    // Bước 3: Giải mã AES-CBC
//    vector<unsigned char> decryptedBytes = aes_cbc_decrypt(cipherBytes, key, ivBytes);
//
//    // Bước 4: Bỏ padding để lấy chuỗi gốc
//    string decryptedText = unpadString(decryptedBytes);
//
//    // Bước 5: Parse AuthenticatorC
//    AuthenticatorC auth = parseAuthenticator(decryptedText);
//
//    // Bước 6: Xác thực
//    if (auth.clientID != client.getID()) {
//        return "mismatch!";
//    }
//    if (auth.realmc != client.getRealm()) {
//        return "mismatch!";
//    }
//
//    auto now = chrono::system_clock::now();
//    if (now < auth.TS2) {
//        return "Timestamp is too early!";
//    }
//
//    // Bước 7: Trả về subkey
//    return auth.subkey;
//}

string processServiceResponse(const string& decryptMessage, ) {

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
