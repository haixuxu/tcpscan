
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <pthread.h>
#include "tcpscan.h"

#define  msg(fmt,arg...) do{printf(fmt,##arg);fflush(stdout);}while(0)



bool    _isLog = false;
bool    _isBanner = false;
bool    _isRangeScan;
bool    _isSinglePort;
bool    _isBreak;
bool    _isMultiplePort;


uint32_t *_portsArray;
int  _portCount;

//保存网络字节序IP
uint32_t  _bindIpAddr;
uint32_t  _startIp;
uint32_t  _endIp;

unsigned long   _portToScan;
unsigned long   _portScanSingle;
unsigned long   _portsTotal;
unsigned long   _totalPortsOpen;
unsigned long   _ipScanned;
unsigned long   _currentIp;

unsigned long   _tcpTimeout = 3;
unsigned long   _maxThreads;
unsigned long   _threadsUsed;


const char *_logFile = "Result.txt"; // idb
char _httpRequest[] = "HEAD / HTTP/1.0\r\n\r\n";



typedef void * HANDLE;
bool _isHttp = false;
int g_IsTimeToShutDown=0;

typedef struct LpParamsTag {
    uint32_t  addr_h;
    uint16_t  port_h;
} LpParams;

unsigned GetTickCount() {
    struct timeval tv;
    if(gettimeofday(&tv, NULL) != 0)
        return 0;

    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

void filterScanPort(PortRange *portrange){
    _portCount = portrange->count;
    _portsArray = malloc(sizeof(uint32_t) * _portCount);

    uint8_t *port_list = portrange->g_portlist;
    int i,offset=0;
    for(i=1;i<0xFFFF;i++){
        if(*(port_list+i)==1){
            *(_portsArray + offset) = i;
            offset++;
        }
    }
}

void *snifferThread( void *ptr ) {
    int sock_raw = 0; // raw socket for sniff
    int  data_size;
    socklen_t saddr_size;
    struct sockaddr saddr;

    unsigned char buffer[65536];// = (unsigned char *)malloc(65536); //Its Big!

    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);

    if (sock_raw < 0) {
        printf("Socket Error\n");
        fflush(stdout);
        return NULL;
    }

    saddr_size = sizeof(saddr);
    while (!g_IsTimeToShutDown) {
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if (data_size < 0 ) {
            printf("%s", "Recvfrom error , failed to get packets\n");
            return NULL;
        }
        //Now process the packet
//        process_packet(buffer , data_size);
    }
    close(sock_raw);
}
void *synScan(){
    printf(" not implement...\n");
    return 0;
}
void *tcpScanThread(void *arg){
    int   sock;         //socket descriptor
    pthread_detach(pthread_self());
    LpParams  *lp_params = (LpParams *)arg;
    fd_set fdset;
    struct timeval tv;

    struct sockaddr_in servaddr;   //socket structure
    struct in_addr destIp;

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(lp_params->port_h); //set the portno
    destIp.s_addr = lp_params->addr_h;
    servaddr.sin_addr = destIp;

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); //created the tcp socket
    if (sock == -1) {
        perror("Socket() error \n");
        _threadsUsed--;
        exit(-1);
    }

//    printf("exec --child---thread--%s:%d\n", inet_ntoa(destIp),lp_params->port_h);
//    without select version
//    int revl = connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr));
//    if (revl == 0) {
//        printf("%-16s %-5d  Open             \n", inet_ntoa(destIp), lp_params->port_h);
//    }
//    close(sock);         //socket descriptor

    fcntl(sock, F_SETFL, O_NONBLOCK);
    connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr));

    while(1) {
        FD_ZERO(&fdset); //每次循环都要清空集合，否则不能检测描述符变化
        FD_SET(sock,&fdset); //添加描述符
        switch(select(sock+1,NULL,&fdset,NULL,&tv)) {//select使用
            case -1:
                exit(-1); //select错误，退出程序
            case 0:
//                printf("waiting sock can usage....\n");
                sleep(5);
                break; //再次轮询
            default:
                if(FD_ISSET(sock,&fdset)) {//测试sock是否可读，即是否网络上有数据
                    int sock_error;
                    int len = sizeof(sock_error);
                    getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_error, &len);
                    if (sock_error == 0) {
                        printf("%-16s %-5d  Open             \n", inet_ntoa(destIp), lp_params->port_h);
                    }
                    goto __destory;
                }
        }
    }
    __destory:
        close(sock);
        free(lp_params);
        _threadsUsed--;

}
int startScan(char * scanType, char * startIpAddr, char * endIpAddr, char * portString, char *maxThreads){

    int sock_raw=0;
    int portIndex=0;
    char bipstr[100] = {0};
    char start_ipstr[100] = {0};
    char end_ipstr[100] = {0};

    int currentIp;

    signed int isSynScan; // [sp+260h] [bp-1Ch]@3

    pthread_t sniffer_thread;
    pthread_t pth;
    LpParams *lpParameter; // [sp+8h] [bp-274h]@119

    IpRange *iprange=malloc(sizeof(IpRange *));
    PortRange *portrange=malloc(sizeof(PortRange *));

    _bindIpAddr=get_local_ip("1.2.4.8"); //获取本地绑定IP
    parse_ip_str(startIpAddr,endIpAddr,iprange); //解析IP列表
    parse_port_str(portString,portrange); //解析端口列表

    filterScanPort(portrange);

    _bindIpAddr = htonl(_bindIpAddr);
    _startIp = htonl(iprange->start_addr);
    _endIp = htonl(iprange->end_addr);

    printf("%X\n", _bindIpAddr); //网络字节序列
    printf("%X\n", _startIp); //网络字节序列
    printf("%X\n", _endIp);   //网络字节序列


    uint32_to_ipstr(_bindIpAddr, bipstr);
    uint32_to_ipstr(_startIp, start_ipstr);
    uint32_to_ipstr(_endIp, end_ipstr);


    printf("----------------------scan options----------------------\n");
    printf("    ScanType:%s\n", scanType);
    printf("    bind_ip :%s\n", bipstr);
    printf("    start_ip:%s\n", start_ipstr);
    printf("    end_ip  :%s\n", end_ipstr);
    printf("    starport:%d\n", *(_portsArray));
    printf("    lastport:%d\n", *(_portsArray+_portCount-1));
    printf("------------------------scaning-------------------------\n");
    if ( strcasecmp(scanType, "SYN") && strcasecmp(scanType, "TCP") ) {
        printf("Invalid Scan Type\n");
        return 0;
    }

    isSynScan=!strcasecmp(scanType, "SYN");

    if ( isSynScan) { //syn
//        _maxThreads = 1;
//        printf("Bind On IP: %d.%d.%d.%d\n\n", (_bindIpAddr & 0x0000ff),
//               ((_bindIpAddr & 0x00ff00) >> 8), ((_bindIpAddr & 0xff0000 ) >> 16), (_bindIpAddr >> 24));
//
//        g_IsTimeToShutDown = 0;
//        if ( pthread_create( &sniffer_thread , NULL ,  snifferThread , NULL) < 0) {
//            printf("Could not create sniffer thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
//            goto __faild;
//        }
//
//        ++_threadsUsed;
//        synScan();
//        while ( _threadsUsed ) {
//            printf("%d Threads Are In Process......              \r", _threadsUsed);
//            if ( previousCount + 1 != _maxThreads ) {
//                sleep(10);
//                if ( isSynScan )
//                    continue;
//            }
//            break;
//        }
//        if (isSynScan )
//            sleep(500);

    } else { //tcp
        _maxThreads = atoi(maxThreads);
        if ( !_maxThreads || (unsigned int)_maxThreads > 0x400 ) {
            printf("Max Thread Out Of Bound\n");
            return 0;
        }

        currentIp = _startIp;
        while ( currentIp <= (int)_endIp ) { //网络字节序列比较
            portIndex = 0;
            while ( portIndex < _portCount ) {

                lpParameter = malloc(sizeof(LpParams *));
                lpParameter->addr_h=ntohl(currentIp);
                lpParameter->port_h=*_portsArray+portIndex;
//                printf("portIndex:%d:port->%d\n",portIndex, *_portsArray+portIndex);
                if (pthread_create(&pth, NULL, tcpScanThread, (void *)lpParameter) != 0) {
                    perror("pthread_creat fail!");
                    goto __faild;
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
    goto __faild;

    __faild:
    if ( sock_raw != -1 )
        close(sock_raw);
    if ( _portsArray ){
        free(_portsArray);
        free(iprange);
    }
    return 1;
}
int help(char * app) {
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
    return printf("Example: %s SYN 12.12.12.12 21,80,3389\n", app);
}

int main(int argc, char **argv)
{
    int ret;
    printf("TCP Port Scanner V1.0 By x373241884y\n\n");

    if ( argc == 4 || argc == 5 || argc == 6 || argc == 7 || argc == 8 || argc == 9 ) {
        int arg = argc;
        for (int i = 1; i <= 3; i++) {
            if (!strcasecmp(argv[argc - i], "/Save")) {
                _isLog = true;
            } else if (!strcasecmp(argv[argc - i], "/Banner")) {
                _isBanner = true;
            } else if (!strcasecmp(argv[argc - i], "/HBanner")) {
                _isBanner = true;
                _isHttp = true;
            } else if (!strncasecmp(argv[argc - i], "/T",2)) {
                _tcpTimeout = atoi(argv[argc - i]+2);
                if (!_tcpTimeout) {
                    printf("Invalid timeout value\n");
                    return -1;
                }
            } else {
                continue;
            }

            arg--;
        }

        switch ( arg ) {
            case 4:
                startScan(argv[1], argv[2], 0, argv[3], "1");
                break;
            case 5:
                if (!strcasecmp(argv[1], "SYN") )
                    startScan(argv[1], argv[2], argv[3], argv[4], "1");
                else
                    startScan(argv[1], argv[2], 0, argv[3], argv[4]);

                break;
            case 6:
                startScan(argv[1], argv[2], argv[3], argv[4], argv[5]);
                break;
        }
        ret = 0;
    }
    else {
        help(argv[0]);
        ret = -1;
    }
    return ret;
}