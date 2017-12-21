
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <pthread.h>
#include "tcpscan.h"


typedef struct LpParamsTag {
    uint32_t addr_h;
    uint16_t port_h;
} LpParams;

bool isSynScan = false;
bool _isLog = false;
bool _isBanner = false;
bool _isRangeScan;
bool _isSinglePort;
bool _isBreak;
bool _isMultiplePort;


uint32_t *_portsArray;
int _portCount;
int _syn_pack_wait = 0;
int _buffer_size = 256; //sniffer cache buffer size

//保存网络字节序IP
uint32_t _bindIpAddr;
uint32_t _startIp;
uint32_t _endIp;

unsigned long _portToScan;
unsigned long _portScanSingle;
unsigned long _portsTotal;
unsigned long _totalPortsOpen;
unsigned long _ipScanned;
unsigned long _currentIp;

unsigned long _tcpTimeout = 3;
unsigned long _maxThreads;
unsigned long _threadsUsed;


const char *_logFile = "Result.txt"; // idb
char _httpRequest[] = "HEAD / HTTP/1.0\r\n\r\n";


typedef void *HANDLE;
bool _isHttp = false;

void print_buffer(unsigned char* buffer,int len) {
    int i = 0;
    int offset = 0;
    int row = 0;

    while (i < len) {
        if(i==0){
            printf("0x00000000:");
        }
        printf("%02X", *(buffer + i));
        if(i%2==1){
            printf(" ");
        }
        offset = i % 0x10;
        row = (int) (i / 0x10+1);
        if (offset == 15) {
            printf("\n0x%08X:", row * 16);
        }
        i++;
    }
    printf("\n");
}

unsigned GetTickCount() {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
        return 0;

    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

void printScanOption() {
    char bipstr[100] = {0};
    char start_ipstr[100] = {0};
    char end_ipstr[100] = {0};

    uint32_to_ipstr(_startIp, start_ipstr);
    uint32_to_ipstr(_endIp, end_ipstr);

    printf("%X\n", _bindIpAddr); //网络字节序列
    printf("%X\n", _startIp);    //网络字节序列
    printf("%X\n", _endIp);      //网络字节序列

    printf("----------------------scan options----------------------\n");
    printf("           ScanType :%s\n", isSynScan ? "SYN" : "TCP");
    if (isSynScan) {
        uint32_to_ipstr(_bindIpAddr, bipstr);
        printf("           BindIp   :%s\n", bipstr);
    }
    printf("           StartIp  :%s\n", start_ipstr);
    printf("           EndIp    :%s\n", end_ipstr);
    printf("           StartPort:%d\n", *(_portsArray));
    printf("           LastPort :%d\n", *(_portsArray + _portCount - 1));
    printf("           MaxThread:%d\n", _maxThreads);
    printf("------------------------scaning-------------------------\n");
}

void filterScanPort(PortRange *portrange) {
    _portCount = portrange->count;
    _portsArray = malloc(sizeof(uint32_t) * _portCount);

    uint8_t *port_list = portrange->g_portlist;
    int i, offset = 0;
    for (i = 1; i < 0xFFFF; i++) {
        if (*(port_list + i) == 1) {
            *(_portsArray + offset) = i;
            offset++;
        }
    }
}

int buildSynPacket(char *buf, u_long saddr, u_long sport, u_long daddr, u_long dport) {
    int len = 0;
    IP_HEADER ip_header;
    TCP_HEADER tcp_header;
    PSD_HEADER psd_header;
    //填充IP首部
    ip_header.h_lenver = (4 << 4 | 5);
    ip_header.tos = 0;
    //高四位IP版本号，低四位首部长度
    ip_header.total_len = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER)); //16位总长度（字节）
    ip_header.ident = 1; //16位标识
    ip_header.frag_and_flags = 0; //3位标志位
    ip_header.ttl = 128; //8位生存时间TTL
    ip_header.proto = IPPROTO_TCP; //8位协议(TCP,UDP…)
    ip_header.checksum = 0; //16位IP首部校验和
    ip_header.sourceIP = saddr; //32位源IP地址
    ip_header.destIP = daddr; //32位目的IP地址

//    printf("%X\n", saddr);
//    printf("%X\n", daddr);

    //填充TCP首部
    tcp_header.th_sport = sport; //源端口号
    tcp_header.th_lenres = (sizeof(TCP_HEADER) / 4 << 4 | 0); //TCP长度和保留位
    tcp_header.th_win = htons(0x4000);

    //填充TCP伪首部（用于计算校验和，并不真正发送）
    psd_header.saddr = ip_header.sourceIP;
    psd_header.daddr = ip_header.destIP;
    psd_header.mbz = 0;
    psd_header.ptcl = IPPROTO_TCP;
    psd_header.tcpl = htons(sizeof(tcp_header));


    tcp_header.th_dport = dport; //目的端口号
    tcp_header.th_ack = 0; //ACK序列号置为0
//    当SYN=1而ACK=0时，表明这是一个连接请求报文。
    tcp_header.th_flag = 0x02; //SYN 标志 00000010
    tcp_header.th_seq = sport - 1; //SYN序列号随机
    tcp_header.th_urp = 0; //偏移
    tcp_header.th_sum = 0; //校验和
    //计算TCP校验和，计算校验和时需要包括TCP pseudo header
    memcpy(buf, &psd_header, sizeof(psd_header));
    memcpy(buf + sizeof(psd_header), &tcp_header, sizeof(tcp_header));
    tcp_header.th_sum = checkSum(buf, sizeof(psd_header) + sizeof(tcp_header));

    //计算IP校验和
    memcpy(buf, &ip_header, sizeof(ip_header));
    memcpy(buf + sizeof(ip_header), &tcp_header, sizeof(tcp_header));
    memset(buf + sizeof(ip_header) + sizeof(tcp_header), 0, 4);
    len = sizeof(ip_header) + sizeof(tcp_header);
    ip_header.checksum = checkSum(buf, len);
    //填充发送缓冲区
    memcpy(buf, &ip_header, sizeof(ip_header));
//    printf("--------------------send packet hex---------------------\n");
//    print_buffer(buf, len);
//    printf("--------------------------------------------------------\n");
//    printf("tos:%X\n", ip_header.tos);
    return len;
}

/**
 * @param buffer
 * @param size
 */
void process_packet(unsigned char *buffer, int size) {
    if (size < 40) {
        printf("receive packet size so small...\n");
        return;
    }
//    printf("--------------------recv packet hex---------------------\n");
//    print_buffer(buffer, size);
//    printf("--------------------------------------------------------\n");

    //Get the IP Header part of this packet
    IP_HEADER *iph = (IP_HEADER *) buffer;

//    printf("%02X ", iph->tos); //1字节
//    printf("%04X ", iph->total_len); //2字节 读取颠倒....
    char remote_ipstr[100] = {0};
    int packet_faddr = ntohl(iph->sourceIP);

    if (packet_faddr < _startIp || packet_faddr > _endIp) { //不是要扫描的IP
        return;
    }
    uint32_to_ipstr(packet_faddr, remote_ipstr);
//    printf("process_packet---%s---th_sport:%d,th-flag:%d\n", remote_ipstr, ntohs(tcph->th_sport), tcph->th_flag);
    //-------|CWR|ECE|URG|ACK|PSH|RST|SYN|FIN|
    //-------| 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
//    uint syn = tcph->th_flag & 0x02;
//    uint ack = tcph->th_flag & 0x10; 6012
    if (*(buffer+33)==0x12) { //00010010 收到确认ACK+SYN包,表明可用,收到ACK+RST包表明不可用
//        TCP_Send(ntohs(testtcp->th_sport),4) ; //send RST packet to close connect
        printf("%-16s %-5d  Open             \n", remote_ipstr, *(buffer+21));
    }
    _syn_pack_wait--;
}

void *snifferThread(void *ptr) {
    int data_size;
//    unsigned char buffer[1024]; //局部变亮，传递到另外一个函数会丢失缓冲区数据
    unsigned char *buffer = (unsigned char *) malloc(_buffer_size); //1024字节足够了...
    memset(buffer, 0, _buffer_size); //不清除缓冲区数据,记录包的大小，减少cpu执行时间

    //Create a raw socket that shall sniff
    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);//嗅探TCP类型的包

    if (sock_raw < 0) {
        printf("You requested a scan type which requires root privileges.\n");
        exit(-1);
    }
    while (1) {
        //Receive a packet
        data_size = recvfrom(sock_raw, buffer, _buffer_size, 0, NULL, NULL); //man 3 recvfrom help me
        if (data_size < 0) {
            printf("%s", "Recvfrom error , failed to get packets\n");
            break;
        }
        //Now process the packet
        process_packet(buffer, data_size);
    }
    close(sock_raw);
    free(buffer);
    printf("Sniffer finished.");
}

void synScan() {
    int portIndex;
    int currentIp = _startIp;
    char buf[0x100] = {0};//256 byte

//    memset(buf, 0, sizeof(buf));

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    //IP_HDRINCL to tell the kernel that headers are included in the packet
    socket_timeoutset(sockfd);
    while (currentIp <= (int) _endIp) { //网络字节序列比较
        portIndex = 0;
        while (portIndex < _portCount) {

            static uint32_t seed = 0x2b;
            int port = *(_portsArray + portIndex);
            int len = 0;
            struct sockaddr_in addr;

            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = ntohl(currentIp);
            addr.sin_port = htons(port);
            srandom(seed++);
            len = buildSynPacket(buf, ntohl(_bindIpAddr), htons(random() % 0x3FFF + 0xC000), ntohl(currentIp),
                                 addr.sin_port);
//            printf("sendto %s:%d --------\n", inet_ntoa(addr.sin_addr), port);
            if (sendto(sockfd, buf, len, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                printf("Error sending syn packet. Error number : %d . Error message : %s \n", errno, strerror(errno));
            }
            _syn_pack_wait++;
            portIndex++;
        }
        ++currentIp;
    }
}

void *tcpScanThread(void *arg) {
    int sockfd;         //socket descriptor
    pthread_detach(pthread_self());
    LpParams *lp_params = (LpParams *) arg;
    fd_set fdset;
    struct timeval tv;

    struct sockaddr_in servaddr;   //socket structure
    struct in_addr destIp;

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(lp_params->port_h); //set the portno
    destIp.s_addr = lp_params->addr_h;
    servaddr.sin_addr = destIp;

    sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); //created the tcp socket
    if (sockfd == -1) {
        perror("Socket() error \n");
        _threadsUsed--;
        exit(-1);
    }
    socket_timeoutset(sockfd);
    printf("exec --child---thread--%s:%d\n", inet_ntoa(destIp), lp_params->port_h);

    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));

    while (1) {
        FD_ZERO(&fdset); //每次循环都要清空集合，否则不能检测描述符变化
        FD_SET(sockfd, &fdset); //添加描述符
        switch (select(sockfd + 1, NULL, &fdset, NULL, &tv)) {//select使用
            case -1:
                exit(-1); //select错误，退出程序
            case 0:
//                printf("waiting sock can usage....\n");
                sleep(5);
                break; //再次轮询
            default:
                if (FD_ISSET(sockfd, &fdset)) {//测试sock是否可读，即是否网络上有数据
                    int sock_error;
                    int len = sizeof(sock_error);
                    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sock_error, &len);
                    if (sock_error == 0) {
                        printf("%-16s %-5d  Open             \n", inet_ntoa(destIp), lp_params->port_h);
                    }
                    goto __destory;
                }
        }
    }
    __destory:
    close(sockfd);
    free(lp_params);
    _threadsUsed--;

}

int startScan(char *scanType, char *startIpAddr, char *endIpAddr, char *portString, char *maxThreads) {

    int sock_raw = 0;
    int portIndex = 0;


    int currentIp;

    pthread_t sniffer_thread;
    pthread_t pth;
    LpParams *lpParameter; // [sp+8h] [bp-274h]@119

    IpRange *iprange = malloc(sizeof(IpRange *));
    PortRange *portrange = malloc(sizeof(PortRange *));

    if (strcasecmp(scanType, "SYN") && strcasecmp(scanType, "TCP")) {
        printf("Invalid Scan Type\n");
        return 0;
    }
    isSynScan = !strcasecmp(scanType, "SYN");

    _bindIpAddr = get_local_ip("1.2.4.8"); //获取本地绑定IP
    parse_ip_str(startIpAddr, endIpAddr, iprange); //解析IP列表
    parse_port_str(portString, portrange); //解析端口列表

    filterScanPort(portrange);

    _startIp = htonl(iprange->start_addr);
    _endIp = htonl(iprange->end_addr);

    if (isSynScan) { //syn
        _maxThreads = 1; //单线程
        _bindIpAddr = htonl(_bindIpAddr);
        printScanOption();
        if (pthread_create(&sniffer_thread, NULL, snifferThread, NULL) < 0) {
            printf("Could not create sniffer thread. Error number : %d . Error message : %s \n", errno,
                   strerror(errno));
            goto __clean;
        }
        synScan();
        pthread_join(sniffer_thread, NULL);
    } else { //tcp  使用多线程
        _maxThreads = atoi(maxThreads);
        printScanOption();
        if (!_maxThreads || (unsigned int) _maxThreads > 0x400) {
            printf("Max Thread Out Of Bound\n");
            return 0;
        }

        currentIp = _startIp;
        while (currentIp <= (int) _endIp) { //网络字节序列比较
            portIndex = 0;
            while (portIndex < _portCount) {

                lpParameter = malloc(sizeof(LpParams *));
                lpParameter->addr_h = ntohl(currentIp);
                lpParameter->port_h = *(_portsArray + portIndex);
//                printf("portIndex:%d:port->%d\n",portIndex, *(_portsArray+portIndex);
                if (pthread_create(&pth, NULL, tcpScanThread, (void *) lpParameter) != 0) {
                    perror("pthread_creat fail!");
                    goto __clean;
                }
                _threadsUsed++;
                portIndex++;
                while (_threadsUsed >= _maxThreads) {
//                    printf("current thread in process----:%d\n",_threadsUsed);
                    sleep(5);
                }
            }
            ++currentIp;
        }
    }
    printf("scan finished.\n");

    goto __clean;

    __clean:
    if (sock_raw != -1)
        close(sock_raw);
    if (_portsArray) {
        free(_portsArray);
        free(iprange);
    }
    return 1;
}


int main(int argc, char **argv) {
    int ret;
    printf("TCP Port Scanner V1.0 By x373241884y\n\n");

    if (argc == 4 || argc == 5 || argc == 6 || argc == 7 || argc == 8 || argc == 9) {
        int arg = argc;
        for (int i = 1; i <= 3; i++) {
            if (!strcasecmp(argv[argc - i], "/Save")) {
                _isLog = true;
            } else if (!strcasecmp(argv[argc - i], "/Banner")) {
                _isBanner = true;
            } else if (!strcasecmp(argv[argc - i], "/HBanner")) {
                _isBanner = true;
                _isHttp = true;
            } else if (!strncasecmp(argv[argc - i], "/T", 2)) {
                _tcpTimeout = atoi(argv[argc - i] + 2);
                if (!_tcpTimeout) {
                    printf("Invalid timeout value\n");
                    return -1;
                }
            } else {
                continue;
            }

            arg--;
        }

        switch (arg) {
            case 4:
                startScan(argv[1], argv[2], 0, argv[3], "1");
                break;
            case 5:
                if (!strcasecmp(argv[1], "SYN"))
                    startScan(argv[1], argv[2], argv[3], argv[4], "1");
                else
                    startScan(argv[1], argv[2], 0, argv[3], argv[4]);

                break;
            case 6:
                startScan(argv[1], argv[2], argv[3], argv[4], argv[5]);
                break;
        }
        ret = 0;
    } else {
        help(argv[0]);
        ret = -1;
    }
    return ret;
}