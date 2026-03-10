#include "consts.h"
#include "security.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

int sockfd = -1;

void handle_signal(int sig) {
    printf("Received signal %d\n", sig);
    if (sockfd > -1) {
        close(sockfd);
        exit(sig);
    }
}

void hostname_to_ip(const char* hostname, char* ip) {
    struct hostent* he;
    struct in_addr** addr_list;

    if ((he = gethostbyname(hostname)) == NULL) {
        fprintf(stderr, "Error: Invalid hostname\n");
        exit(255);
    }

    addr_list = (struct in_addr**) he->h_addr_list;

    for (int i = 0; addr_list[i] != NULL; i++) {
        strcpy(ip, inet_ntoa(*addr_list[i]));
        return;
    }

    fprintf(stderr, "Error: Invalid hostname\n");
    exit(255);
}

int main(int argc, char** argv) {
    // Register signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGQUIT, handle_signal);

    if (argc < 3) {
        fprintf(stderr, "Usage: client <hostname> <port> \n");
        exit(1);
    }

    /* Create sockets */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket open failed");
        exit(1);
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    // use IPv4  use UDP

    /* Construct server address */
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET; // use IPv4
    char addr[100] = {0};
    hostname_to_ip(argv[1], addr);
    server_addr.sin_addr.s_addr = inet_addr(addr);
    // Set sending port
    int PORT = atoi(argv[2]);
    server_addr.sin_port = htons(PORT); // Big endian

    init_sec(CLIENT_CLIENT_HELLO_SEND, argv[1], argc > 3);
    // Connect to server
    if (connect(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed");
        exit(1);
    }

    // Set the socket nonblocking
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int) {1}, sizeof(int));

    while(1) {
        // printf("connected\n");
        char recv_buffer[5000] = {0};
        char send_buffer[5000] = {0};

        // send data
size_t sent = input_sec((uint8_t*)send_buffer, sizeof(send_buffer));
        if (sent > 0) send(sockfd, send_buffer, sent, 0);

        // receive data
        ssize_t recvd = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
        if (recvd > 0) {
            fprintf(stderr, "received %zd bytes\n", recvd);
            output_sec((uint8_t*)recv_buffer, recvd);
        }        else if (recvd == 0) break;
        else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // send data
            size_t sent = input_sec((uint8_t*)send_buffer, sizeof(send_buffer));
            if (sent > 0) send(sockfd, send_buffer, sent, 0);
        } else {
            perror("connection went bad");
            break;
        }
    }
    close(sockfd);
    return 0;
}
