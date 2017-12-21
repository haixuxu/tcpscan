#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "tcplib.h"

uint8_t g_port_list[0xFFFF] = {0}; //要扫描的端口相应的位会被置1

void help(char *app) {
    printf("Usage:   %s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]\n", app);
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 80 512\n", app);
    printf("Example: %s TCP 12.12.12.12/24 80 512\n", app);
    printf("Example: %s TCP 12.12.12.12/24 80 512 /T8 /Save\n", app);
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 80 512 /HBanner\n", app);
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 21 512 /Banner\n", app);

    printf("Example: %s TCP 12.12.12.12 1-65535 512\n", app);
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 21,3389,5631 512\n", app);
    printf("Example: %s TCP 12.12.12.12 21,3389,5631 512\n", app);
    printf("Example: %s SYN 12.12.12.12 12.12.12.254 80\n", app);
    printf("Example: %s SYN 12.12.12.12 1-65535\n", app);
    printf("Example: %s SYN 12.12.12.12 12.12.12.254 21,80,3389\n", app);
    printf("Example: %s SYN 12.12.12.12 21,80,3389\n", app);
}
void socket_timeoutset(int sockfd){
    struct timeval timeout_s, timeout_r;
    timeout_s.tv_sec = 1;
    timeout_s.tv_usec = 0;
    timeout_r.tv_sec = 3;
    timeout_r.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout_r, sizeof(timeout_r)) < 0) {
        perror("setsockopt failed\n");
        exit(-1);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout_s, sizeof(timeout_s)) < 0) {
        perror("setsockopt failed\n");
        exit(-1);
    }
}
void uint32_to_ipstr(uint32_t ip, char *ip_ptr) { //使用网络字节序列
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(ip_ptr, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
//    printf("%s\n", ip_ptr);
}

uint16_t checkSum(void *buffer, int size) {
    uint32_t cksum = 0;
    while (size > 1) {
        cksum += *(uint16_t *) buffer;
        size -= sizeof(uint16_t);
        buffer = (char *) buffer + sizeof(uint16_t);
    }
    if (size) cksum += *(uint16_t *) buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (uint16_t) (~cksum);
}

/*
* 得到本地要绑定的 ip
*/
uint32_t get_local_ip(char *dstIpAddr) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    int dns_port = 53;
    int err;
    struct sockaddr_in serv;
    struct sockaddr_in local;
    socklen_t locallen = sizeof(local);
    memset(&serv, 0, sizeof(serv));
    memset(&local, 0, sizeof(local));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(dstIpAddr);//inet_addr(HostName);
    serv.sin_port = htons(dns_port);
    err = connect(sock, (const struct sockaddr *) &serv, sizeof(serv));
    err = getsockname(sock, (struct sockaddr *) &local, &locallen);
    if (-1 == err) { //failed
        exit(EXIT_FAILURE);
    }
    close(sock);
    return local.sin_addr.s_addr;
}

uint32_t hostname_to_ip(char *hostname) {
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    if ((he = gethostbyname(hostname)) == NULL) {
        herror("gethostbyname");
        return 1;
    } else {
        addr_list = (struct in_addr **) he->h_addr_list;
        for (i = 0; addr_list[i] != NULL; i++) {
            return addr_list[i]->s_addr;
        }
    }
}

void parse_port_str(char *poststr, PortRange *port_range) {
    int idx, count = 0;
    char *temp = strtok(poststr, ",");
    while (temp) {
//        printf("%s \n",temp);
        uint16_t start, end;
        char *slash = NULL;
        char port[64] = {0};
        if ((slash = strchr(temp, '-'))) { //23-1000

            strncpy(port, temp, strlen(temp) - strlen(slash)); //1-65535 ==> 1
            start = atoi(port);
            end = atoi(slash + 1);

            if (end < start) {
                continue;
            }
            for (idx = start; idx <= end; idx++) {
                g_port_list[idx] = 1;
                count++;
            }
        } else {
            start = atoi(temp);
            g_port_list[start] = 1;
            count++;
        }
        temp = strtok(NULL, ",");
    }
    port_range->g_portlist = g_port_list;
    port_range->count = count;
}

void parse_ip_str(char *startIpAddr, char *endIpAddr, IpRange *ipinfo) {
    char startIpStr[256];
    char *slash = NULL;
    unsigned int range = 0;
    unsigned int submask = 0;

    memset(startIpStr, 0, sizeof(startIpStr));

    if (!endIpAddr) {
        slash = strchr(startIpAddr, '/'); //get "/24"
        if (slash) {
            strncpy(startIpStr, startIpAddr, strlen(startIpAddr) - strlen(slash)); //192.168.0.0/24 ==> 192.168.0.0
            int bit = atoi(slash + 1); //24
            range = 0xFFFFFFFF >> bit;
            submask = 0xFFFFFFFF << (32 - bit);
//
            ipinfo->start_addr = (inet_addr(startIpStr) & ntohl(submask)) + ntohl(1);    //保存4字节IP主机字节序
            ipinfo->end_addr = (inet_addr(startIpStr) & ntohl(submask)) + ntohl(range - 1);//保存4字节IP主机字节序
        } else {
            // 起始IP参数转化(支持域名)
            uint32_t ipaddr = hostname_to_ip(startIpAddr);
            ipinfo->start_addr = ipaddr;//保存4字节IP主机字节序
            ipinfo->end_addr = ipaddr;  //保存4字节IP主机字节序
        }
    }

}