# tcpscan
port scan like s

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

# bat scan with batscan.sh

```sh
[toor@door src]$ cat ips.txt 
192.168.0.0/24
168.235.85.0/24
```

```sh
[root@door src]# ./batscan.sh ips.txt 
start scan 22...
exec ./tcpscan syn 192.168.0.0/24 22 /Save
TCP/SYN Port Scanner V1.0 By x373241884y

_bindIp  mem>>C0A80275
_startIp mem>>C0A80001
_endIp   mem>>C0A800FE
----------------------scan options----------------------
           ScanType :SYN
           BindIp   :192.168.2.117
           StartIp  :192.168.0.1
           EndIp    :192.168.0.254
           StartPort:22
           LastPort :22
------------------------scaning-------------------------
total scan tasks:254
scan finished.

exec ./tcpscan syn 168.235.85.0/24 22 /Save
TCP/SYN Port Scanner V1.0 By x373241884y

_bindIp  mem>>C0A80275
_startIp mem>>A8EB5501
_endIp   mem>>A8EB55FE
----------------------scan options----------------------
           ScanType :SYN
           BindIp   :192.168.2.117
           StartIp  :168.235.85.1
           EndIp    :168.235.85.254
           StartPort:22
           LastPort :22
------------------------scaning-------------------------
total scan tasks:254
168.235.85.7     22     Open             
168.235.85.38    22     Open             
168.235.85.46    22     Open             
168.235.85.17    22     Open             
168.235.85.23    22     Open             
168.235.85.45    22     Open             
168.235.85.37    22     Open             
168.235.85.78    22     Open             
168.235.85.43    22     Open             
168.235.85.52    22     Open             
168.235.85.87    22     Open             
168.235.85.20    22     Open             
168.235.85.22    22     Open             
168.235.85.50    22     Open             
168.235.85.109   22     Open             
168.235.85.62    22     Open             
168.235.85.127   22     Open             
168.235.85.105   22     Open             
168.235.85.106   22     Open             
168.235.85.85    22     Open             
168.235.85.108   22     Open             
168.235.85.51    22     Open             
168.235.85.48    22     Open             
168.235.85.116   22     Open             
168.235.85.169   22     Open             
168.235.85.149   22     Open             
168.235.85.139   22     Open             
168.235.85.103   22     Open             
168.235.85.178   22     Open             
168.235.85.112   22     Open             
168.235.85.94    22     Open             
168.235.85.132   22     Open             
168.235.85.157   22     Open                      
scan finished.
```
