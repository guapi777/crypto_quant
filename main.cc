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

static int sockfd;

ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *user_data) {
    char buf2[4096];
    ssize_t nbytes = recv(sockfd, buf2, len, 0);
    if (nbytes == -1) {
        // handle error
    }
    char str[len + 1];
    memcpy(str, buf, len);
    str[len] = '\0';
    //printf("%s\n", str);

    return nbytes;
}


ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data) {
    printf("%d ", data[0]);
    printf("%d ", data[1]);
    printf("%d ", data[2]);
    printf("%d ", data[3]);
    printf("%d \n", data[4]);


    struct Session *session = (struct Session *) user_data;


    int ret = send(sockfd, data, len, flags);
    if (ret == -1) {
        fprintf(stderr, "send() failed: %s\n", strerror(errno));
        return -1;

    }
    return 0;
}

int genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data) {

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

int connect_addr(const char *host_name, const char *service) {
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
    SSL *ssl = SSL_new(ctx);
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
            std::cerr << "Error: could not establish SSL connection\n";
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
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

int recv_http_handshake(int fd, std::string &resheader) {
    char buf2[4096];
    while (true) {
        ssize_t r;
        (r = recv(fd, buf2, 4096, 0));
        if (r <= 0) {
            return -1;
        }
        resheader.append(buf2, buf2 + r);
        if (resheader.find("\r\n\r\n") != std::string::npos) {
            break;
        }
        if (resheader.size() > 8192) {
            std::cerr << "Too big response header" << std::endl;
            return -1;
        }
    }
    return 0;
}

int send_http_handshake(int fd, const std::string &reqheader) {
    size_t off = 0;
    while (off < reqheader.size()) {
        ssize_t r;
        size_t len = reqheader.size() - off;
        while ((r = send(fd, reqheader.c_str() + off, len, 0)) == -1 && errno == EINTR);
        if (r == -1) {
            perror("write");
            return -1;
        }
        off += r;
    }
    return 0;
}

int http_handshake(const char *host, const char *service,
                   const char *path, std::string &body) {
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
             path, host, client_key.c_str()); //
    std::cout << buf << std::endl;
    std::string reqheader = buf;
    if (send_http_handshake(sockfd, reqheader) == -1) {
        return -1;
    }
    std::string resheader;
    if (recv_http_handshake(sockfd, resheader) == -1) {
        return -1;
    }
    std::string::size_type keyhdstart;
    if ((keyhdstart = resheader.find("Sec-WebSocket-Accept: ")) ==
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
    char service[] = "8433";
    char path[] = "/ws/v5/public";
    wslay_event_context_ptr wslay_ctx;
    std::string body;

    if (connect_addr(host_name, service) == -1) {
        return -1;
    }

    struct wslay_event_callbacks callbacks = {
            .recv_callback= recv_callback,
            .send_callback = send_callback,
            .genmask_callback = genmask_callback,
            .on_frame_recv_start_callback = on_frame_recv_start_callback,
            .on_frame_recv_chunk_callback  =on_frame_recv_chunk_callback,
            .on_frame_recv_end_callback = on_frame_recv_end_callback,
            .on_msg_recv_callback = on_msg_recv_callback,
    };


    if (wslay_event_context_client_init(&wslay_ctx, &callbacks, nullptr) != 0) {
        fprintf(stderr, "Failed to initialize wslay_event_context.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }


    if (http_handshake(host_name, service, path, body) == -1) {
        std::cerr << "Failed handshake" << std::endl;
        close(sockfd);
        return -1;
    }

    //wslay_event_queue_msg(wslay_ctx, &event_msg);


    if (wslay_event_want_write(wslay_ctx)) {
        int ret = wslay_event_send(wslay_ctx);

        if (ret != 0) {
            fprintf(stderr, "Error sending data with wslay: %d\n", ret);
            return -1;
        }
    }
    wslay_event_recv(wslay_ctx);

    wslay_event_context_free(wslay_ctx);

    return 0;
}
