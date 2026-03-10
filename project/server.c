#include "consts.h"
#include "security.h"
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

int sockfd = -1;
int clientfd = -1;

void handle_signal(int sig) {
    printf("Received signal %d\n", sig);
    if (clientfd > -1) {
        close(clientfd);
        clientfd = -1;
    }
    if (sockfd > -1) {
        close(sockfd);
        sockfd = -1;
    }
    exit(sig);
}


int main(int argc, char** argv) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGQUIT, handle_signal);

    if (argc < 2) {
        fprintf(stderr, "Usage: server <port>\n");
        exit(1);
    }

    /* Create sockets */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(1);
    }
    // use IPv4  use UDP

    /* Construct our address */
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET; // use IPv4
    server_addr.sin_addr.s_addr =
        INADDR_ANY; // accept all connections
                    // same as inet_addr("0.0.0.0")
                    // "Address string to network bytes"
    // Set receiving port
    int PORT = atoi(argv[1]);
    server_addr.sin_port = htons(PORT); // Big endian

    // Let operating system know about our config */
    if (bind(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        handle_signal(SIGTERM);
    }

    // Listen for new clients
    int did_find_client = listen(sockfd, 1);
    if (did_find_client < 0) {
        perror("listen failed");
        handle_signal(SIGTERM);
    }

    struct sockaddr_in client_addr; // Same information, but about client
    socklen_t client_size = sizeof(client_addr);

    // Accept client connection
    clientfd = accept(sockfd, (struct sockaddr*) &client_addr, &client_size);
    if (clientfd < 0) {
        perror("accept failed");
        handle_signal(SIGTERM);
    }
    // Set the socket nonblocking
    int flags = fcntl(clientfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(clientfd, F_SETFL, flags);
    setsockopt(clientfd, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
    setsockopt(clientfd, SOL_SOCKET, SO_REUSEPORT, &(int) {1}, sizeof(int));

    if (clientfd < 0) return errno;
    init_sec(SERVER_CLIENT_HELLO_AWAIT, NULL, argc > 2);
    while (clientfd) {
        char recv_buffer[5000] = {0};
        char send_buffer[5000] = {0};
        // receive data
        ssize_t recvd = recv(clientfd, &recv_buffer, sizeof(recv_buffer), 0);
        if (recvd > 0) {
            fprintf(stderr, "received %zd bytes\n", recvd);
            output_sec((uint8_t*)recv_buffer, recvd);
        }
        else if (recvd == 0) break;
        else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // send data
            size_t sent = input_sec((uint8_t*)send_buffer, sizeof(send_buffer));
            if (sent > 0) send(clientfd, send_buffer, sent, 0);
        } else {
            perror("connection went bad");
            break;
        }
    }
    close(clientfd);
    close(sockfd);
    return 0;
}
