#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <wslay/wslay.h>
#include <arpa/inet.h>
#include <openssl/rand.h>


#define PROXY_HOST "127.0.0.1"
#define PROXY_PORT 7890
static int sockfd;

ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *user_data) {
    ssize_t nbytes = recv(sockfd, buf, len, 0);
    if (nbytes == -1) {
        // handle error
    }
    char str[len+1];
    memcpy(str, buf, len);
    str[len] = '\0';
    printf("%s\n", str);

    return nbytes;
}

ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data) {

    int ret = send(sockfd, data, len, flags);
    if (ret == -1) {
        fprintf(stderr, "send() failed: %s\n", strerror(errno));
        return -1;

    }
    return 0;
}

int genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data) {

    if (RAND_bytes(buf, (int) len) != 1) {
        return -1;
    }

    return 0;
}

void
on_frame_recv_start_callback(wslay_event_context_ptr ctx, const struct wslay_event_on_frame_recv_start_arg *arg,
                             void *user_data) {
    printf("on_frame_recv_start_callback\n");

}

void
on_frame_recv_chunk_callback(wslay_event_context_ptr ctx, const struct wslay_event_on_frame_recv_chunk_arg *arg,
                             void *user_data) {
    printf("on_frame_recv_chunk_callback\n");
}

void
on_frame_recv_end_callback(wslay_event_context_ptr ctx, void *user_data) {
    printf("on_frame_recv_end_callback\n");
}

void on_msg_recv_callback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg, void *user_data) {
    printf("on_msg_recv_callback\n");

}


int main(int argc, char *argv[]) {



    // get binance address info
    struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP,
    };
    struct addrinfo *result, *rp;

    int s = getaddrinfo("ws.okx.com", "8443", &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(s));
        return EXIT_FAILURE;
    }

    // 设置代理服务器
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = inet_addr(PROXY_HOST);
    proxy_addr.sin_port = htons(PROXY_PORT);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sock, (struct sockaddr *) &proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("connect error");
        exit(1);
    }


    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            continue;
        }
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1) {
            break;
        }
        close(sockfd);
    }


    if (rp == NULL) {
        /* No address succeeded */
        fprintf(stderr, "Could not connect to Binance API server\n");
        return EXIT_FAILURE;
    }


    wslay_event_context_ptr ctx;
    struct wslay_event_callbacks callbacks = {
            .send_callback = send_callback,
            .recv_callback= recv_callback,
            .genmask_callback = genmask_callback,
            .on_frame_recv_start_callback = on_frame_recv_start_callback,
            .on_frame_recv_chunk_callback  =on_frame_recv_chunk_callback,
            .on_frame_recv_end_callback = on_frame_recv_end_callback,
            .on_msg_recv_callback = on_msg_recv_callback,
    };


    if (wslay_event_context_client_init(&ctx, &callbacks, NULL) != 0) {
        fprintf(stderr, "Failed to initialize wslay_event_context.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }


    // 发送 WebSocket 握手请求
    char *request = "GET /ws HTTP/1.1\r\n"
                    "Host: ws.okx.com\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
                    "Sec-WebSocket-Version: 13\r\n"
                    "\r\n";

    struct wslay_event_msg event_msg = {
            .msg = (uint8_t *) request,
            .msg_length = strlen(request),
    };

    wslay_event_queue_msg(ctx, &event_msg);

    if (wslay_event_want_write(ctx)) {
        int ret = wslay_event_send(ctx);

        if (ret != 0) {
            fprintf(stderr, "Error sending data with wslay: %d\n", ret);
            return -1;
        }
    }
    wslay_event_recv(ctx);
    freeaddrinfo(result);
    wslay_event_context_free(ctx);

    return 0;
}
