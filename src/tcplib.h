//
// Created by toor on 17-12-20.
//

#ifndef TCPSCAN_TCPLIB_H
#define TCPSCAN_TCPLIB_H

typedef struct  IPRange{ //声明一种类型,IPRange是类型的标签，或者说是类型的元数据
    uint32_t start_addr;
    uint32_t end_addr;
}IpRange; //类型命名

typedef struct {
    int  count;//port count
    uint8_t  *g_portlist;
}PortRange;

void uint32_to_ipstr(uint32_t ip,char *ip_ptr);
uint32_t get_local_ip (char * dstIpAddr);
uint32_t hostname_to_ip(char *hostname);

void parse_ip_str(char * startIpAddr,char * endIpAddr,IpRange *ip_range);
void parse_port_str(char * poststr,PortRange *port_range);

#endif //TCPSCAN_TCPLIB_H
