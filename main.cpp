#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

int is_blocked(const char *host, const char* target_domain) {

    if (strstr(host, target_domain) != NULL) {
        return 1;
    }

    return 0;
}

void usage() {
    printf("syntax: netfilter-test <domain>\n");
    printf("sample: netfilter-test test.gilgil.net\n");
}

bool isHarmfulSite(unsigned char *payload, int payload_len, const char *target_domain) {
    struct iphdr *ip = (struct iphdr *)payload;
    if (ip->protocol != IPPROTO_TCP) return false;

    int ip_header_len = ip->ihl * 4;
    if (payload_len < ip_header_len + sizeof(struct tcphdr)) return false;

    struct tcphdr *tcp = (struct tcphdr *)(payload + ip_header_len);
    int tcp_header_len = tcp->doff * 4;

    int http_offset = ip_header_len + tcp_header_len;
    if (payload_len <= http_offset) return false;

    char *http = (char *)(payload + http_offset);
    int http_len = payload_len - http_offset;

    char http_buf[2048] = {0};
    int copy_len = http_len < sizeof(http_buf) - 1 ? http_len : sizeof(http_buf) - 1;
    memcpy(http_buf, http, copy_len);

    char *host = strstr(http_buf, "Host:");
    if (host) {
        host += 5;
        while (*host == ' ') host++;

        char domain[256] = {0};
        sscanf(host, "%255s", domain);

        if (strstr(domain, target_domain)) {
            printf("❌ 차단 도메인입니다: %s\n", domain);
            return true;
        }
    }
    return false;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d\n", ret);

    fputc('\n', stdout);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    const char* Hamful_domain = (const char*)data;
    unsigned char *payload;
    int payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len > 0) {
        if(isHarmfulSite(payload, payload_len, Hamful_domain))
            return nfq_set_verdict(qh, print_pkt(nfa), NF_DROP, 0, NULL);
    }
    return nfq_set_verdict(qh, print_pkt(nfa), NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        usage();
        return EXIT_FAILURE;
    }
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    //struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, (void*)argv[1]);
    if (!qh) {
        perror("nfq_create_queue");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

/*
sudo iptables -F
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -j NFQUEUE --queue-num 0
*/
