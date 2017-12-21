# tcpscan
tcpscan

gcc ./tcpscan.c ./tcplib.c -o tcpscan  -lpthread

```sh
[toor@localhost src]$ ./tcpscan
TCP Port Scanner V1.0 By x373241884y

Usage:   ./tcpscan TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]
Example: ./tcpscan TCP 12.12.12.12 12.12.12.254 80 512
Example: ./tcpscan TCP 12.12.12.12/24 80 512
Example: ./tcpscan TCP 12.12.12.12/24 80 512 /T8 /Save
Example: ./tcpscan TCP 12.12.12.12 12.12.12.254 80 512 /HBanner
Example: ./tcpscan TCP 12.12.12.12 12.12.12.254 21 512 /Banner
Example: ./tcpscan TCP 12.12.12.12 1-65535 512
Example: ./tcpscan TCP 12.12.12.12 12.12.12.254 21,3389,5631 512
Example: ./tcpscan TCP 12.12.12.12 21,3389,5631 512
Example: ./tcpscan SYN 12.12.12.12 12.12.12.254 80
Example: ./tcpscan SYN 12.12.12.12 1-65535
Example: ./tcpscan SYN 12.12.12.12 12.12.12.254 21,80,3389
Example: ./tcpscan SYN 12.12.12.12 21,80,3389
```
