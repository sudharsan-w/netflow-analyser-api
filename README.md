Current Process:
NetFlow File -> Parses it as ingests flow and users -> Filters flags with Exclusions -> Map Blacklists

From the netflow file:
we can parse the raw format and then store the raw in a collection for future lookups and store the main attributes in a flow collection. this staged parsing enables the addition of 
more features like flow duration to be added.

Run:
```sh
python3 process_netflow.py
```

Generation and Versions of Netflow:
To Monitor the Traffic and send it to a Exporter
```sh
sudo softflowd -d -i eth0 -n 127.0.0.1:2055 -v 9 # version 9 netflow 
sudo softflowd -d -i eth0 -n 127.0.0.1:2055 # version 5 netflow
sudo softflowd -d -i eth0 -n 127.0.0.1:2055 -v 10 # IPFIX
```

for the exporter:
```sh
sudo nfcapd -D -p 2055 -l ~/flows
```
for the decoded data from the flows directory:
```sh
nfdump -r /var/log/flows/nfcapd.* -o long   # core fields
nfdump -r /var/log/flows/nfcapd.* -o raw    # all template fields
```
Samples for each version:
v5:
```txt
Flow Record:
  RecordCount  =                 10
  Flags        =               0x00 NETFLOW v5, Unsampled
  Elements     =                  3: 1 2 12
  size         =                 84
  engine type  =                  0
  engine ID    =                  0
  export sysid =                  1
  first        =      1744987004988 [2025-04-18 20:06:44.988]
  last         =      1744987005274 [2025-04-18 20:06:45.274]
  received at  =      1744988713659 [2025-04-18 20:35:13.659]
  proto        =                  6 TCP
  tcp flags    =               0x1b ...AP.SF
  src port     =              37404
  dst port     =                443
  src tos      =                  0
  fwd status   =                  0
  in packets   =                 13
  in bytes     =               1921
  src addr     =       10.50.50.173
  dst addr     =    142.250.195.234
  ip exporter  =          127.0.0.1
```
v9;
```txt
Flow Record:
  RecordCount  =               8798
  Flags        =               0x02 NETFLOW v9, Sampled
  Elements     =                  5: 1 2 4 12 38
  size         =                140
  engine type  =                  0
  engine ID    =                  0
  export sysid =                  2
  first        =      1745001873242 [2025-04-19 00:14:33.242]
  last         =      1745001892902 [2025-04-19 00:14:52.902]
  received at  =      1745001900485 [2025-04-19 00:15:00.485]
  proto        =                  6 TCP
  tcp flags    =               0x02 ......S.
  src port     =              33906
  dst port     =                443
  src tos      =                  0
  fwd status   =                  0
  in packets   =                  9
  in bytes     =                540
  src addr     =        192.168.0.7
  dst addr     =       52.35.150.14
  input        =                  0
  output       =                  0
  src mask     =                  0 /0
  dst mask     =                  0 /0
  dst tos      =                  0
  direction    =                  0
  biFlow Dir   =               0x00
  end reason   =               0x00
  ip exporter  =          127.0.0.1
  vlanID       =                  0
  post vlanID  =                  0
  custID       =                  0
  post custID  =                  0
  ingress IfID =                  0
  egress IfID  =                  0
  ethertype    =             0x0000
  IP version   =                  4
```
v10:
```txt

Flow Record:
  RecordCount  =               8816
  Flags        =               0x02 NETFLOW v10, Sampled
  Elements     =                  5: 1 2 4 12 38
  size         =                140
  engine type  =                  0
  engine ID    =                  0
  export sysid =                  3
  first        =      1745002555370 [2025-04-19 00:25:55.370]
  last         =      1745002555629 [2025-04-19 00:25:55.629]
  received at  =      1745002681435 [2025-04-19 00:28:01.435]
  proto        =                  6 TCP
  tcp flags    =               0x06 .....RS.
  src port     =              54766
  dst port     =                443
  src tos      =                  0
  fwd status   =                  0
  in packets   =                  2
  in bytes     =                100
  src addr     =        192.168.0.7
  dst addr     =     142.250.196.10
  input        =                  0
  output       =                  0
  src mask     =                  0 /0
  dst mask     =                  0 /0
  dst tos      =                  0
  direction    =                  0
  biFlow Dir   =               0x00
  end reason   =               0x00
  ip exporter  =          127.0.0.1
  vlanID       =                  0
  post vlanID  =                  0
  custID       =                  0
  post custID  =                  0
  ingress IfID =                  0
  egress IfID  =                  0
  ethertype    =             0x0000
  IP version   =                  4
```
