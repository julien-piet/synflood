# synflood
Flooding a TCP port with SYN messages

USAGE :

synflood ip port [rest_time]
ip : IP address, eg. 192.168.1.1
port : destination port, eg. 80
rest_time : time between two SYN dispatches in micro seconds. Default is 50. 0 is allowed for maximum rate. 
