# title fake-clodflare-tell-me-to-open-cmd

# summary

lowkey I wanna download some file and I got autoreddect and got some "fake" clodflare

# inicial access

the web similar look like this: (I forgot to screenshot but similar look like this)


characteristic :can't minimize,ordered to open cmd 

# tecnical analysis 
I try to cntrl + v and got this:



Decode IP: 3112851607 -> 185.138.88.151
flow attacker: trungle.txt = loader, Z595.ps1 = stealer
total 4 file 

# IOCS 
IP: 185.138.88.151
URL: hxxp://185.138.88.151/438
URL: hxxp://185.138.88.151/439
File: trungle.txt
File: Z595.ps1
File: q6ytyo0.exe
ASN: GCS_SER-NET

# infrastructure 
RDAP: https://www.virustotal.com/gui/ip-address/185.138.88.151/details

-Network Name: GCS_SER-NET
Address Range: 185.138.88.0 - 185.138.88.255
CIDR: 185.138.88.0/24

-Parent Network: 185.138.88.0 - 185.138.91.255

-registration: 2025-08-11
last changed: 2025-08-11

-characteristic infrastructure: Create a new IP -> used to spread malware for 2-3 months -> discovered -> delete -> create a new one.

-i try scan in virustotal and got 4 file detected that speaking /connecting to hacker server

link result: https://www.virustotal.com/gui/ip-address/185.138.88.151/relations

# mitigation 

-never open cmd when download some game 

-cloudflare never tell YOU to open cmd

-download in official web

-if cant escape maximaze try f11 or alt + f4
