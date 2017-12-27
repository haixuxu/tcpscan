# tcpscan
tcpscan

gcc ./tcpscan.c ./tcplib.c -o tcpscan  -lpthread -lrt

```sh
[toor@localhost src]$ ./tcpscan
TCP/SYN Port Scanner V1.0 By x373241884y

Usage:   ./tcpscan TCP/SYN StartIP [EndIP] Ports [/T(N)] [/t(sec)] [/(H)Banner] [/Save]
Example: ./tcpscan TCP 12.12.12.12 12.12.12.254 80 /T512
Example: ./tcpscan TCP 12.12.12.12/24 80 /T512
Example: ./tcpscan TCP 12.12.12.12/24 80 /T512 /t5 /Save
Example: ./tcpscan TCP 12.12.12.12 12.12.12.254 80 /T512 /HBanner
Example: ./tcpscan TCP 12.12.12.12 12.12.12.254 21 /T512 /Banner
Example: ./tcpscan TCP 12.12.12.12 1-65535 /T512
Example: ./tcpscan TCP 12.12.12.12 12.12.12.254 21,3389,5631 /T512
Example: ./tcpscan TCP 12.12.12.12 21,3389,5631 /T512
Example: ./tcpscan SYN 12.12.12.12 12.12.12.254 80
Example: ./tcpscan SYN 12.12.12.12 1-65535
Example: ./tcpscan SYN 12.12.12.12 12.12.12.254 21,80,3389
Example: ./tcpscan SYN 12.12.12.12 21,80,3389

```

- /T set threads for tcp scan
- /t set tcp connect timeout
- /Save save scan log to Result.txt