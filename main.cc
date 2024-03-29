#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cerrno>
#include <sys/socket.h>
#include <netdb.h>
#include <wslay/wslay.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <iostream>
#include <fstream>
#include <nettle/base64.h>
#include <nettle/sha.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>

static int sockfd;
static SSL *ssl;
static const uint8_t makskey[] = {0x37u, 0xfau, 0x21u, 0x3du};

int make_non_block(int fd) {
    int flags, r;
    while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR);
    if (flags == -1) {
        return -1;
    }
    while ((r = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR);
    if (r == -1) {
        return -1;
    }
    return 0;
}

void ctl_epollev(int epollfd, int op, wslay_event_context_ptr &ws) {
    epoll_event ev{};
    memset(&ev, 0, sizeof(ev));
    if (wslay_event_want_read(ws)) {
        ev.events |= EPOLLIN;
    }
    if (wslay_event_want_write(ws)) {
        ev.events |= EPOLLOUT;
    }
    if (epoll_ctl(epollfd, op, sockfd, &ev) == -1) {
        perror("epoll_ctl");
        exit(EXIT_FAILURE);
    }
}

ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *user_data) {
    std::cout << "___recv_callback____" << "len= " << len << std::endl;
    int r = SSL_read(ssl, buf, len);
    while (r > 0) {
        std::string_view stringView1((char *) buf, r);

        std::cout << stringView1 << std::endl;

        r = SSL_read(ssl, buf, sizeof(buf));
    }


    return 0;
}


ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data) {
    ssize_t r;
    r = SSL_write(ssl, data, len);
    if (r == -1) {
        perror("write");
        return -1;
    }
    return r;
}

int genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data) {
    std::cout << "genmask_callback" << std::endl;
    memcpy(buf, makskey, 4);
    return 0;

}

void on_msg_recv_callback(wslay_event_context_ptr ctx,
                          const struct wslay_event_on_msg_recv_arg *arg,
                          void *user_data) {


    std::cout << "on_msg_recv_callback" << std::endl;

}


std::string base64(const std::string &src) {
    base64_encode_ctx ctx{};
    base64_encode_init(&ctx);
    int dstlen = BASE64_ENCODE_RAW_LENGTH(src.size());
    char *dst = new char[dstlen];
    base64_encode_raw(dst, src.size(),
                      reinterpret_cast<const uint8_t *>(src.c_str()));
    std::string res(&dst[0], &dst[dstlen]);
    delete[] dst;
    return res;
}

std::string sha1(const std::string &src) {
    sha1_ctx ctx{};
    sha1_init(&ctx);
    sha1_update(&ctx, src.size(), reinterpret_cast<const uint8_t *>(src.c_str()));
    uint8_t temp[SHA1_DIGEST_SIZE];
    sha1_digest(&ctx, SHA1_DIGEST_SIZE, temp);
    std::string res(&temp[0], &temp[SHA1_DIGEST_SIZE]);
    return res;
}


std::string create_acceptkey(const std::string &clientkey) {
    std::string s = clientkey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    return base64(sha1(s));
}

auto get_random16() {
    char buf[16];
    std::fstream f("/dev/urandom");
    f.read(buf, 16);
    return std::string(buf, buf + 16);
}

int connect_addr(const char *host_name, const int service) {

    SSL_set_tlsext_host_name(ssl, host_name);

    // 创建TCP socket连接
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *host = gethostbyname(host_name);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = *(in_addr_t *) host->h_addr_list[0];
    memset(addr.sin_zero, '\0', sizeof(addr.sin_zero));
    if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        std::cerr << "Error: Failed to connect to server" << std::endl;
        return -1;
    }

    // 将SSL连接与socket关联
    SSL_set_fd(ssl, sockfd);

    // 建立 SSL 连接
    for (int i = 0; i <= 10; i++) {
        if (i == 10) {
            return -1;
        }

        if (SSL_connect(ssl) == -1) {
            std::cout << "Error: Failed to establish SSL connection,retry connect num:" << i << std::endl;
        } else {
            break;
        }

    }

    // 输出连接成功的信息
    std::cout << "SSL connection established to " << host_name << ":" << service << std::endl;
    std::cout << "SSL version: " << SSL_get_version(ssl) << std::endl;
    std::cout << "Cipher: " << SSL_get_cipher(ssl) << std::endl;
    std::cout << "-------------------------------" << std::endl;

    return 0;
}

int recv_http_handshake(std::string &resheader) {
    char buf[4096];
    ssize_t r = SSL_read(ssl, buf, sizeof(buf));
    if (r <= 0) {
        return -1;
    }
    buf[r] = '\0';
    // std::cout << buf << std::endl;
    resheader = buf;
    return 0;
}

int send_http_handshake(const std::string &reqheader) {
    ssize_t r;
    r = SSL_write(ssl, reqheader.c_str(), reqheader.length());
    if (r == -1) {
        perror("write");
        return -1;
    }
    return 0;
}

int http_handshake(const char *host, const char *path, std::string &body) {

    char buf[4096];
    std::string client_key = base64(get_random16());
    snprintf(buf, sizeof(buf),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "\r\n",
             path, host, client_key.c_str());
    std::string reqheader = buf;
    if (send_http_handshake(reqheader) == -1) {
        return -1;
    }
    std::string resheader;
    if (recv_http_handshake(resheader) == -1) {
        return -1;
    }
    std::string::size_type keyhdstart;
    if ((keyhdstart = resheader.find("sec-websocket-accept: ")) ==
        std::string::npos) {
        std::cerr << "http_upgrade: missing required headers" << std::endl;
        return -1;
    }
    keyhdstart += 22;
    std::string::size_type keyhdend = resheader.find("\r\n", keyhdstart);
    std::string accept_key = resheader.substr(keyhdstart, keyhdend - keyhdstart);
    if (accept_key == create_acceptkey(client_key)) {
        body = resheader.substr(resheader.find("\r\n\r\n") + 4);
        return 0;
    } else {
        return -1;
    }
}

int main(int argc, char *argv[]) {

    char host_name[] = "ws.okx.com";
    char path[] = "/ws/v5/public";
    //char host_name[] = "testnet.binance.com";
    //char path[] = "/ws-api/v3";
    int service = 433;

    std::string body;

    // 初始化 OpenSSL 库
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // 创建一个 SSL_CTX 对象
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Error: could not create SSL context\n";
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 创建SSL连接
    ssl = SSL_new(ctx);

    if (connect_addr(host_name, service) == -1) {
        std::cerr << "Error: could not establish SSL connection\n";
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    if (http_handshake(host_name, path, body) == -1) {
        std::cerr << "Failed handshake" << std::endl;
        close(sockfd);
        return -1;
    } else {
        std::cout << "success handshake" << std::endl;
        std::cout << "-------------------------------" << std::endl;
    }

    wslay_event_context_ptr wslay_event_ctx;
    struct wslay_event_callbacks event_callbacks = {
            recv_callback,
            send_callback,
            genmask_callback,
            nullptr, /* on_frame_recv_start_callback */
            nullptr, /* on_frame_recv_callback */
            nullptr, /* on_frame_recv_end_callback */
            //nullptr,
            on_msg_recv_callback, /* on_msg_recv_callback */

    };

    if (wslay_event_context_client_init(&wslay_event_ctx, &event_callbacks, nullptr) != 0) {
        fprintf(stderr, "Failed to initialize wslay_event_context.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }


    std::string msg = R"({
    "id": "1512",
    "op": "order",
    "args": [{
        "side": "buy",
        "instId": "BTC-USDT",
        "tdMode": "isolated",
        "ordType": "market",
        "sz": "100"
    }]
}
)";
    wslay_event_msg event_msg = {
            .opcode = WSLAY_TEXT_FRAME,
            .msg =(uint8_t *) msg.c_str(),
            .msg_length = msg.size()
    };

    wslay_event_queue_msg(wslay_event_ctx, &event_msg);
    make_non_block(sockfd);
    int val = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t) sizeof(val)) ==
        -1) {
        perror("setsockopt: TCP_NODELAY");
        return -1;
    }
    int epollfd = epoll_create(1);
    ctl_epollev(epollfd, EPOLL_CTL_ADD, wslay_event_ctx);
    static const size_t MAX_EVENTS = 1;
    epoll_event events[MAX_EVENTS];

    bool ok = true;
    while (wslay_event_want_read(wslay_event_ctx) || wslay_event_want_write(wslay_event_ctx)) {
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait");
            return -1;
        }
        for (int n = 0; n < nfds; ++n) {
            if (((events[n].events & EPOLLIN) && wslay_event_recv(wslay_event_ctx) != 0) ||
                ((events[n].events & EPOLLOUT) && wslay_event_send(wslay_event_ctx) != 0)) {
                ok = false;
                break;
            }
        }
        if (!ok) {
            break;
        }
        ctl_epollev(epollfd, EPOLL_CTL_MOD, wslay_event_ctx);
    }

    // wslay_event_send(wslay_event_ctx);
    // wslay_event_recv(wslay_event_ctx);
    wslay_event_context_free(wslay_event_ctx);

    return 0;
}
