from scapy.all import *

WEATHER_IP = "34.218.16.79"
def main():
    check = 1
    choose = 5000
    while choose != 0:
        choose = int(input("""Please select sniffing state:
1. DNS 
2. Forecast
3. HTTP
or 0 to exit!!!!!!!!!!!!!!!!!
HERE==>"""))
        if choose == 1:
            packet = sniff(count = 20,lfilter=dns_filt,prn=print_packet_ex1)
        elif choose == 2:
            packet = sniff(count = 20, lfilter = ex2_filt,prn=print_packet_ex2)
        elif choose == 3:
            packet = sniff(count = 20, lfilter = ex3_filt,prn= ex3_print)
        elif choose == 0:
            quit()
    """
    will act as the filter for ex1
    input:packet
    output:none
    """
def dns_filt(packet):
    return (DNS in packet) and ("Ans" in packet.summary()) and (TCP in packet)

    """
    will act as the print for ex1
    input:packet
    output:none
    """
def print_packet_ex1(packet):
    print(str(packet[DNS].qd.qname, "utf-8"),"ip is",packet[IP].dst)
    """
    will act as the filter for ex2
    input:packet
    output:none
    """
def ex2_filt(packet):
    return WEATHER_IP in packet.summary() and Raw in packet  and "Welcome" not in packet[Raw].load.decode()
    """
    will act as the print for ex2
    input:packet
    output:none
    """
def print_packet_ex2(packet):
    print(packet[Raw].load.decode())

    """
    will act as the filter for ex3
    input:packet
    output:none
    """
def ex3_filt(packet):
    if Raw in packet:
        if b'GET' in packet[Raw].load:
            return True
    return False

    """
    will act as the print for ex3
    input:packet
    output:none
    """
def ex3_print(packet):
    packet = packet[Raw].load.decode().split('\n')
    packet = packet[0]
    second = packet.find("HTTP")
    print(packet[4:second])
    #print(packet[2:second])
#packet[2:packet[Raw].decode().find("HTTP")]

main()


