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

typedef struct LpParamsTag {
    uint32_t addr_h;
    uint16_t port_h;
} LpParams;

//option
bool isSynScan = false;
bool _isLog = false;
bool _isBanner = false;
bool _isHttp = false;
uint16_t *_portsArray;
int _portCount;
uint32_t _startIp; //内存值为big order
uint32_t _endIp;   //内存值为big order

IpRange *iprange;
PortRange *portrange;

int log_fd;  // for log
unsigned long _scantasks = 0;
unsigned long _donetasks = 0;

//SYN option
//保存网络字节序IP
uint32_t _bindIpAddr;
char sniffer_buf[256];
//char write_buf[1024]; //write file cache

//TCP option
unsigned int _tcpTimeout = 3;
unsigned int _maxThreads=1;
ThreadPool *thpool;
pthread_mutex_t lock;

const char *_logFile = "Result.txt"; // idb
char _httpRequest[] = "HEAD / HTTP/1.0\r\n\r\n";

void spwritelog(const char *format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    int rc = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    printf(buffer);
    if (_isLog) {
        int ret = write(log_fd, buffer, rc);
        if(ret < 0 ) {
            printf("write result file failed !!\n");
        }
    }
}

void freemem() {
    free(_portsArray);
    free(iprange);
    free(portrange);
    if (!isSynScan) {
        threadpool_destroy(thpool, 0);
    }
    if(_isLog){
        close(log_fd);
    }
}

void printScanOption() {
    char bipstr[100] = {0};
    char start_ipstr[100] = {0};
    char end_ipstr[100] = {0};

    printf("_bindIp  mem>>%X\n", _bindIpAddr);
    printf("_startIp mem>>%X\n", _startIp);
    printf("_endIp   mem>>%X\n", _endIp);

    uint32_to_ipstr(_startIp, start_ipstr);
    uint32_to_ipstr(_endIp, end_ipstr);

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
    if (!isSynScan) {
        printf("           MaxThread:%d\n", _maxThreads);
    }
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
    //高四位IP版本号，低四位首部长度
    ip_header.h_lenver = (4 << 4 | 5);
    ip_header.tos = 0;
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
//    printf("---------------------------send hex---------------------\n");
//    print_buffer(buf, len);
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
//    printf("---------------------------recv hex---------------------\n");
//    print_buffer(buffer, size);

    //Get the IP Header part of this packet
    IP_HEADER *iph = (IP_HEADER *) buffer;
    TCP_HEADER *tcph = (TCP_HEADER *) (buffer + sizeof(TCP_HEADER));
//    printf("%02X ", iph->tos); //1字节
//    printf("%04X ", iph->total_len); //2字节 读取颠倒....
    char remote_ipstr[100] = {0};
    int packet_faddr = ntohl(iph->sourceIP);

    if (packet_faddr < _startIp || packet_faddr > _endIp) { //不是要扫描的IP
        return;
    }
    //完成任务计数
    pthread_mutex_lock(&lock);
    _donetasks++;
    pthread_mutex_unlock(&lock);

    uint32_to_ipstr(packet_faddr, remote_ipstr);
//    printf("process_packet---%s---th_sport:%d\n", remote_ipstr, *(buffer + 21));
    //-------|CWR|ECE|URG|ACK|PSH|RST|SYN|FIN|
    //-------| 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
//    uint syn = tcph->th_flag & 0x02;
//    uint ack = tcph->th_flag & 0x10; 6012
    if (*(buffer + 33) == 0x12) { //00010010 收到确认ACK+SYN包,表明可用,收到ACK+RST包表明不可用
//        print_buffer(buffer, size);
        spwritelog("%-16s %-5d  Open             \n", remote_ipstr, htons(tcph->th_sport));
    }
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
    socket_timeoutset(sock_raw, 3, false); // 3 sec timeout ,close thread
    while (1) {
        //Receive a packet
        data_size = recvfrom(sock_raw, sniffer_buf, sizeof(sniffer_buf), 0, NULL, NULL); //man 3 recvfrom help me
        if (data_size < 0) {
//            printf("%s", "Recvfrom error , failed to get packets\n");
            break;
        }
        //Now process the packet
        process_packet(sniffer_buf, data_size);
    }
    close(sock_raw);
}

void synScan() {
    int portIndex;
    uint32_t currentIp = _startIp;
    char buf[0x100] = {0};//256 byte
    pthread_t sniffer_thread;

//    memset(buf, 0, sizeof(buf));
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd<0){
        printf("You requested a scan type which requires root privileges.\n");
        exit(-1);
    }
    printScanOption(); //print option info

    if (pthread_create(&sniffer_thread, NULL, snifferThread, NULL) < 0) {
        printf("Could not create sniffer thread. Error number : %d . Error message : %s \n", errno,
               strerror(errno));
        freemem();
        exit(-1);
    }

    socket_timeoutset(sockfd, 3, true);
    socket_timeoutset(sockfd, 3, false);
    while (currentIp <= _endIp) { //网络字节序列比较
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
            len = buildSynPacket(buf, ntohl(_bindIpAddr), htons(getrandom(0xC000, 0xFFFF)), ntohl(currentIp), addr.sin_port);
//            printf("sendto %s:%d --------\n", inet_ntoa(addr.sin_addr), port);
            if (sendto(sockfd, buf, len, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                printf("Error sending syn packet. Error number : %d . Error message : %s \n", errno, strerror(errno));
                _donetasks++;
            }
            _scantasks++;
            portIndex++;
        }
        ++currentIp;
    }
    pthread_join(sniffer_thread, NULL);
}


void tcpScanTask(void *arg) {
    int sockfd;         //socket descriptor
    LpParams *lp_params = (LpParams *) arg;
    uint32_t scanIp = lp_params->addr_h;
    uint16_t scanPort = lp_params->port_h;
    free(lp_params);

    pthread_detach(pthread_self());
    fd_set readset;
    struct timeval tv;

    struct sockaddr_in servaddr;   //socket structure
    struct in_addr destIp;

    destIp.s_addr = scanIp;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(scanPort); //set the portno
    servaddr.sin_addr = destIp;
//    printf("exec --child---thread--%s:%d\n", inet_ntoa(destIp), scanPort);
    tv.tv_sec = _tcpTimeout;
    tv.tv_usec = 0;

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //created the tcp socket
    if (sockfd == -1) {
        perror("Socket() error \n");
        goto __destory;
    }
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    int ret = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    int error=0;
    if (ret != -1) {
        goto __recv;
    }
    if (errno == EINPROGRESS) {
//        printf("(-)- EINPROGRESS in connect() - selecting\n");
        while (1) {
            FD_ZERO(&readset);
            FD_SET(sockfd, &readset);
            ret = select(sockfd + 1, NULL, &readset, NULL, &tv);
            /* error which is not an interruption */
            if (ret < 0 && errno != EINTR) {
//                printf("(!) %s - Error from select()\n", inet_ntoa(destIp), errno, strerror(errno));
                goto __destory;
            } else if (ret > 0) {/* socket selected : host up */
                __recv:
                error = 0;
                socklen_t len = sizeof (error);
                int retval = getsockopt (sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
                if (retval != 0||error != 0) {
                    /* there was a problem getting the error code */
//                    printf("socket error: %s\n", strerror(error));
                    goto __destory;
                }
                spwritelog("%-16s %-5d  Open             \n", inet_ntoa(destIp), (int)scanPort);
                break;
            } else {/* timeout case */
//                printf("(!) %s:%d is down (timeout)\n", inet_ntoa(destIp), scanPort);
                break;
            }
        }
    }

    __destory:
    close(sockfd);
    sockfd = -1;
    //完成任务计数
    pthread_mutex_lock(&lock);
    _donetasks++;
    pthread_mutex_unlock(&lock);

}

void tcpScan() {
    int portIndex = 0;
    uint32_t currentIp = _startIp;
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
    printf("Pool started with %d threads and queue size of %d\n", _maxThreads, 65535);
    while (currentIp <= _endIp) { //网络字节序列比较
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
    printf("total scan tasks:%d\n", _scantasks);
    while (1) {
        usleep(15 * 1000);
        if (_scantasks == _donetasks) {
            threadpool_destroy(thpool, 0);
            break;
        }
    }
}

void startScan(char *scanType, char *startIpAddr, char *endIpAddr, char *portString) {

    iprange = malloc(sizeof(IpRange *));
    portrange = malloc(sizeof(PortRange *));

    if (strcasecmp(scanType, "SYN") && strcasecmp(scanType, "TCP")) {
        printf("Invalid Scan Type\n");
        exit(0);
    }
    isSynScan = !strcasecmp(scanType, "SYN");

    if (endIpAddr!=NULL&&!valid_ip_addr(endIpAddr)) {
        printf("Invalid end ip address.\n");
        exit(0);
    }

    parse_ip_str(startIpAddr, endIpAddr, iprange); //解析IP列表
    parse_port_str(portString, portrange); //解析端口列表

    filterScanPort(portrange);

    _startIp = htonl(iprange->start_addr);
    _endIp = htonl(iprange->end_addr);

    if (isSynScan) { //syn
        _maxThreads = 1; //单线程
        _bindIpAddr = get_local_ip("1.2.4.8"); //获取本地绑定IP
        _bindIpAddr = htonl(_bindIpAddr);
        synScan();
    } else { //tcp  使用多线程
        if (!_maxThreads || _maxThreads > 0x400) {
            printf("Max Thread Out Of Bound\n");
            exit(0);
        }
        printScanOption();
        tcpScan();
    }
    spwritelog("scan finished.\n");
    freemem();
    exit(0);
}

int main(int argc, char **argv) {
    int ret;
    printf("TCP/SYN Port Scanner V1.0 By x373241884y\n\n");

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
            } else if (!strncasecmp(argv[argc - i], "/T", 2)) { //set threads
                _maxThreads = atoi(argv[argc - i] + 2);
                if (!_maxThreads) {
                    printf("Invalid threads value\n");
                    exit(-1);
                }
            } else if (!strncasecmp(argv[argc - i], "/t", 2)) { //set tcp timeout
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
        if(arg==4){
            startScan(argv[1], argv[2], NULL, argv[3]); //endIP可选
        }else if(arg==5){
            startScan(argv[1], argv[2], argv[3], argv[4]);
        }else{
            printf("Invalid arguments list\n");
        }
        ret = 0;
    } else {
        help(argv[0]);
        ret = -1;
    }
    return ret;
}