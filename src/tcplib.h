//
// Created by toor on 17-12-20.
//

#ifndef TCPSCAN_TCPLIB_H
#define TCPSCAN_TCPLIB_H

//定义TCP伪报头
typedef struct psd_hdr
{
    uint32_t saddr; //源地址
    uint32_t daddr; //目的地址
    uint8_t mbz; uint8_t ptcl; //协议类型
    uint16_t tcpl; //TCP长度

}PSD_HEADER;

/**
 * tcpdump -nnv -X -r nmap.cap
 * 21:27:43.344829 IP (tos 0x0, ttl 39, id 61740, offset 0, flags [none], proto TCP (6), length 44)
 * 192.168.0.103.53341 > 192.168.0.105.53: Flags [S], cksum 0x0b1e (correct), seq 2150544934, win 1024, options [mss 1460], length 0
    0x0000:  4500 002c f12c 0000 2706 207f c0a8 0067  E..,.,..'......g
    0x0010:  c0a8 0069 d05d 0035 802e b626 0000 0000  ...i.].5...&....
    0x0020:  6002 0400 0b1e 0000 0204 05b4
 */

/**
 * TCP header (20字节+option+padding)
----------
	0x0010:            d05d 0035 802e b626 0000 0000
	0x0020:  6002 0400 0b1e 0000 0204 05b4
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|          Source Port          |       Destination Port        | d05d 0035  (53341 53)
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                        Sequence Number                        | 802e b626  2150544934
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                    Acknowledgment Number                      | 0000 0000
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Data |       |C|E|U|A|P|R|S|F|                               |
	| Offset|  Res. |W|C|R|C|S|S|Y|I|            Window             | 6002 0400
	|       |       |R|E|G|K|H|T|N|N|                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|           Checksum            |         Urgent Pointer        | 0b1e 0000
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                    Options                    |    Padding    | 0204 05b4
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                             data                              |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
//定义TCP报头(20字节)
typedef struct _tcphdr //内存数据全是网络字节序
{
    uint16_t th_sport; //16位源端口
    uint16_t th_dport; //16位目的端口
    uint32_t th_seq; //32位序列号
    uint32_t th_ack; //32位确认号
    uint8_t th_lenres; //4位首部长度+4位保留字
    uint8_t th_flag; //8位标志位
    uint16_t th_win; //16位窗口大小
    uint16_t th_sum; //16位校验和
    uint16_t th_urp; //16位紧急数据偏移量

} TCP_HEADER;

/**
 * IP header (20字节+option+padding)
---------
    0x0000:  4500 002c f12c 0000 2706 207f c0a8 0067
	0x0010:  c0a8 0069
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|Version|  IHL  |Type of Service|          Total Length         | 4500 002c
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|         Identification        |Flags|      Fragment Offset    | f12c 0000
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Time to Live |    Protocol   |         Header Checksum       | 2706 207f
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                       Source Address                          | c0a8 0067   -- 192.168.0.103
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                    Destination Address                        | c0a8 0069   -- 192.168.0.105
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                    Options                    |    Padding    | <-- optional
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                            DATA ...                           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
//定义IP报头(20字节)
typedef struct _iphdr
{
    uint8_t h_lenver ;  //4位首部长度+4位IP版本号
    uint8_t tos;        //8位服务类型TOS
    uint16_t total_len; //16位总长度（字节）
    uint16_t ident;     //16位标识
    uint16_t frag_and_flags; //3位标志位
    uint8_t ttl;        //8位生存时间 TTL
    uint8_t proto;      //8位协议 (TCP, UDP 或其他)
    uint16_t checksum;  //16位IP首部校验和
    uint32_t sourceIP;  //32位源IP地址
    uint32_t destIP;    //32位目的IP地址

} IP_HEADER;

typedef struct  IPRange{ //声明一种类型,IPRange是类型的标签，或者说是类型的元数据
    uint32_t start_addr;
    uint32_t end_addr;
}IpRange; //类型命名

typedef struct {
    int  count;//port count
    uint8_t  *g_portlist;
}PortRange;

//通用函数
int getrandom(int begin, int end);
void help(char * app);
void socket_timeoutset(int sockfd);
void uint32_to_ipstr(uint32_t ip,char *ip_ptr);
//通用函数
uint16_t checkSum(void * buffer, int size);
uint32_t get_local_ip (char * dstIpAddr);
uint32_t hostname_to_ip(char *hostname);
//辅助函数
void parse_ip_str(char * startIpAddr,char * endIpAddr,IpRange *ip_range);
void parse_port_str(char * poststr,PortRange *port_range);


//threadpool
typedef struct threadpool_task_t{ //工作任务
    void (*function)(void *);

    void *argument;
} ThreadTask;
typedef struct threadpool_t { //线程池类型
    pthread_mutex_t lock;
    pthread_cond_t notify;
    pthread_t *threads;
    ThreadTask *queue;
    int thread_count;
    int queue_size;
    int head;
    int tail;
    int count;
    int shutdown;
    int started;
} ThreadPool;
ThreadPool *threadpool_create(int thread_count, int queue_size, int flags);
int threadpool_add(ThreadPool *pool, void (*routine)(void *), void *arg, int flags);
int threadpool_destroy(ThreadPool *pool, int flags);

#endif //TCPSCAN_TCPLIB_H
