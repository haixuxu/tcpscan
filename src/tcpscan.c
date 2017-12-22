
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <pthread.h>
#include "tcpscan.h"

#define _isDebug  false

//调试日志
#define  debugger(fmt, arg...)  do{logcat(1,fmt,##arg);fflush(stdout);}while(0)
//打印并根据条件写入文件
#define  spwritelog(fmt, arg...)  do{logcat(2,fmt,##arg);fflush(stdout);}while(0)

typedef struct LpParamsTag {
    uint32_t addr_h;
    uint16_t port_h;
} LpParams;

bool isSynScan = false;
bool _isLog = false;
bool _isBanner = false;


uint32_t *_portsArray;
int _portCount;
int log_fd;  // for log
int _syn_pack_wait = 0;
char sniffer_buf[256];
//char write_buf[1024]; //write file cache

//保存网络字节序IP
uint32_t _bindIpAddr;
uint32_t _startIp;
uint32_t _endIp;

IpRange *iprange;
PortRange *portrange;

unsigned long _tcpTimeout = 3;
unsigned long _maxThreads;

ThreadPool *thpool;
pthread_mutex_t lock;
unsigned long _scantasks = 0, _donetasks = 0;


const char *_logFile = "Result.txt"; // idb
char _httpRequest[] = "HEAD / HTTP/1.0\r\n\r\n";


typedef void *HANDLE;
bool _isHttp = false;

void print_buffer(unsigned char *buffer, int len, bool issend) {
    if (_isDebug) {
        printf("--------------------recv %s hex---------------------\n", issend ? "send" : "recv");
        int i = 0;
        int offset = 0;
        int row = 0;

        while (i < len) {
            if (i == 0) {
                printf("0x00000000:");
            }
            printf("%02X", *(buffer + i));
            if (i % 2 == 1) {
                printf(" ");
            }
            offset = i % 0x10;
            row = (int) (i / 0x10 + 1);
            if (offset == 15) {
                printf("\n0x%08X:", row * 16);
            }
            i++;
        }
        printf("--------------------------------------------------------\n");
    }
}

void logcat(int type, const char *format, ...) {
    va_list args;
    va_start(args, format);
    if (type == 1) { //debug
        if (_isDebug) {
            vprintf(format, args);
        }
    } else if (type == 2) { //console log and write file....
        vprintf(format, args);
        if (_isLog) {
            vdprintf(log_fd, format, args);
        }
    }
    va_end(args);

}

void freemem() {
    free(_portsArray);
    free(iprange);
    free(portrange);
    if (!isSynScan) {
        threadpool_destroy(thpool, 0);
    }
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
    print_buffer(buf, len, true);
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
    print_buffer(buffer, size, false);

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
    if (*(buffer + 33) == 0x12) { //00010010 收到确认ACK+SYN包,表明可用,收到ACK+RST包表明不可用
        spwritelog("%-16s %-5d  Open             \n", remote_ipstr, *(buffer + 21));
    }
    _syn_pack_wait--;
}

void *snifferThread(void *ptr) {
    int data_size;

    memset(sniffer_buf, 0, sizeof(sniffer_buf)); //不清除缓冲区数据,记录包的大小，减少cpu执行时间
    //Create a raw socket that shall sniff
    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);//嗅探TCP类型的包
    if (sock_raw < 0) {
        printf("You requested a scan type which requires root privileges.\n");
        exit(-1);
    }
    while (1) {
        //Receive a packet
        data_size = recvfrom(sock_raw, sniffer_buf, sizeof(sniffer_buf), 0, NULL, NULL); //man 3 recvfrom help me
        if (data_size < 0) {
            printf("%s", "Recvfrom error , failed to get packets\n");
            break;
        }
        //Now process the packet
        process_packet(sniffer_buf, data_size);
    }
    close(sock_raw);
//    spwritelog("Sniffer finished.");
}

void synScan() {
    int portIndex;
    int currentIp = _startIp;
    char buf[0x100] = {0};//256 byte

//    memset(buf, 0, sizeof(buf));
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd<0){
        printf("You requested a scan type which requires root privileges.\n");
        exit(-1);
    }
    printScanOption(); //print option info
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
            len = buildSynPacket(buf, ntohl(_bindIpAddr), htons(getrandom(0xC000, 0xFFFF)), ntohl(currentIp),
                                 addr.sin_port);
            debugger("sendto %s:%d --------\n", inet_ntoa(addr.sin_addr), port);
            if (sendto(sockfd, buf, len, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                printf("Error sending syn packet. Error number : %d . Error message : %s \n", errno, strerror(errno));
                _donetasks++;
            }
            _scantasks++;
            portIndex++;
        }
        ++currentIp;
    }
}


void tcpScanTask(void *arg) {
    int sockfd;         //socket descriptor
    pthread_detach(pthread_self());
    LpParams *lp_params = (LpParams *) arg;
    fd_set readset;
    struct timeval tv;

    struct sockaddr_in servaddr;   //socket structure
    struct in_addr destIp;

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(lp_params->port_h); //set the portno
    destIp.s_addr = lp_params->addr_h;
    servaddr.sin_addr = destIp;

    tv.tv_sec = 3;
    tv.tv_usec = 0;

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //created the tcp socket
    if (sockfd == -1) {
        perror("Socket() error \n");
        goto __destory;
    }
//    socket_timeoutset(sockfd);
//    debugger("exec --child---thread--%s:%d\n", inet_ntoa(destIp), lp_params->port_h);
    //阻塞式socket
//    int revl = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
//    if (revl == 0) {
//        printf("%-16s %-5d  Open             \n", inet_ntoa(destIp), lp_params->port_h);
//    }
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    int ret = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    int error=0;
    if (ret != -1) {
        printf("herer..r.esflalf\n");
        goto __recv;
    }
    if (errno == EINPROGRESS) {
        debugger("(-)- EINPROGRESS in connect() - selecting\n");
        while (1) {
            FD_ZERO(&readset);
            FD_SET(sockfd, &readset);
            ret = select(sockfd + 1, NULL, &readset, NULL, &tv);
            /* error which is not an interruption */
            if (ret < 0 && errno != EINTR) {
                debugger("(!) %s - Error from select()\n", inet_ntoa(destIp), errno, strerror(errno));
                goto __destory;
            } else if (ret > 0) {/* socket selected : host up */
                __recv:
                error = 0;
                socklen_t len = sizeof (error);
                int retval = getsockopt (sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
                if (retval != 0||error != 0) {
                    /* there was a problem getting the error code */
                    debugger("socket error: %s\n", strerror(error));
                    goto __destory;
                }
                printf("%-16s %-5d  Open             \n", inet_ntoa(destIp), lp_params->port_h);
                break;
            } else {/* timeout case */
                debugger("(!) %s:%d is down (timeout)\n", inet_ntoa(destIp), lp_params->port_h);
                break;
            }
        }
    }

    __destory:
    close(sockfd);
    sockfd = -1;
//    free(lp_params);
    //完成任务计数
    pthread_mutex_lock(&lock);
    _donetasks++;
    pthread_mutex_unlock(&lock);

}

void tcpScan() {
    int portIndex = 0;
    int currentIp = _startIp;
    pthread_t pth;
    LpParams *lpParameter;

    //初始化
    int ret = 0;
    pthread_mutex_init(&lock, NULL);
    thpool = threadpool_create(_maxThreads, 65535, 0);
    if (thpool == NULL) {
        printf("create tcp scan task failed.\b");
        freemem();
        exit(-1);
    }
    fprintf(stderr, "Pool started with %d threads and queue size of %d\n", _maxThreads, thpool->count);
    while (currentIp <= (int) _endIp) { //网络字节序列比较
        portIndex = 0;
        while (portIndex < _portCount) {

            lpParameter = malloc(sizeof(LpParams *));
            lpParameter->addr_h = ntohl(currentIp);
            lpParameter->port_h = *(_portsArray + portIndex);
            _scantasks++; //当前任务添加计数
            ret = threadpool_add(thpool, tcpScanTask, lpParameter, 0);
            if (ret == -1) {
                _scantasks--;
                printf("create tcp scan task failed.\b");
                continue;
            }
            portIndex++;
        }
        ++currentIp;
    }
    while (1) {
        if (_scantasks == _donetasks) {
            threadpool_destroy(thpool, 0);
            printf("scan finished.\n");
            freemem();
            exit(0);
        }
        usleep(15 * 1000);
    }
}

void startScan(char *scanType, char *startIpAddr, char *endIpAddr, char *portString, char *maxThreads) {


    pthread_t sniffer_thread;


    iprange = malloc(sizeof(IpRange *));
    portrange = malloc(sizeof(PortRange *));

    if (strcasecmp(scanType, "SYN") && strcasecmp(scanType, "TCP")) {
        printf("Invalid Scan Type\n");
        exit(0);
    }
    isSynScan = !strcasecmp(scanType, "SYN");


    parse_ip_str(startIpAddr, endIpAddr, iprange); //解析IP列表
    parse_port_str(portString, portrange); //解析端口列表

    filterScanPort(portrange);

    _startIp = htonl(iprange->start_addr);
    _endIp = htonl(iprange->end_addr);

    if (isSynScan) { //syn
        _maxThreads = 1; //单线程
        _bindIpAddr = get_local_ip("1.2.4.8"); //获取本地绑定IP
        _bindIpAddr = htonl(_bindIpAddr);
        if (pthread_create(&sniffer_thread, NULL, snifferThread, NULL) < 0) {
            printf("Could not create sniffer thread. Error number : %d . Error message : %s \n", errno,
                   strerror(errno));
            freemem();
            exit(-1);
        }
        synScan();
        pthread_join(sniffer_thread, NULL);
    } else { //tcp  使用多线程
        _maxThreads = atoi(maxThreads);
        if (!_maxThreads || (unsigned int) _maxThreads > 0x400) {
            printf("Max Thread Out Of Bound\n");
            exit(0);
        }
        printScanOption();
        tcpScan();
    }
}

int main(int argc, char **argv) {
    int ret;
    printf("TCP Port Scanner V1.0 By x373241884y\n\n");

    if (argc == 4 || argc == 5 || argc == 6 || argc == 7 || argc == 8 || argc == 9) {
        int arg = argc;
        for (int i = 1; i <= 3; i++) {
            if (!strcasecmp(argv[argc - i], "/Save")) {
                _isLog = true;
                log_fd = open(_logFile, O_RDWR | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);
                if (log_fd == -1) {
                    printf("Can not create log file .\n");
                    exit(-1);
                }
            } else if (!strcasecmp(argv[argc - i], "/Banner")) {
                _isBanner = true;
            } else if (!strcasecmp(argv[argc - i], "/HBanner")) {
                _isBanner = true;
                _isHttp = true;
            } else if (!strncasecmp(argv[argc - i], "/T", 2)) {
                _tcpTimeout = atoi(argv[argc - i] + 2);
                if (!_tcpTimeout) {
                    printf("Invalid timeout value\n");
                    exit(-1);
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