import time

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff
from scapy.compat import raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether


# 格式化抓取时间
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime


class PacketSnifferThread(QThread):
    packet_captured = pyqtSignal(dict)

    def __init__(self, interface, filter):
        super().__init__()
        self.interface = interface
        self.filter = filter
        self.sniffing = True
        self.paused = False

    def run(self):
        if self.interface == "All" and self.filter == "":
            sniff(prn=self.process_packet, stop_filter=self.should_stop)
        elif self.interface == "All":
            sniff(prn=self.process_packet, filter=self.filter, stop_filter=self.should_stop)
        elif self.filter == "":
            sniff(prn=self.process_packet, iface=self.interface, stop_filter=self.should_stop)
        else:
            sniff(iface=self.interface, prn=self.process_packet, filter=self.filter, stop_filter=self.should_stop)

    def process_packet(self, packet):
        packet_info = dict()
        if self.sniffing and not self.paused:
            packet_time = timestamp2time(packet.time)
            src = packet[Ether].src
            dst = packet[Ether].dst
            type = packet[Ether].type
            types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
            if type in types:
                proto = types[type]
            else:
                proto = 'LOOP'
            # IP
            if proto == 'IPv4':
                protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP',
                          51: 'AH', 58: 'ICMPv6', 89: 'OSPF'}
                src = packet[IP].src
                dst = packet[IP].dst
                proto = packet[IP].proto
                if proto in protos:
                    proto = protos[proto]
            # tcp
            if packet.haslayer(TCP):
                protos = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP',
                              110: 'POP3', 143: 'IMAP'}
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                if sport in protos:
                    proto = protos[sport]
                elif dport in protos:
                    proto = protos[dport]
            elif packet.haslayer(UDP):
                protos = {53: 'DNS', 69: 'TFTP'}
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                if sport in protos:
                    proto = protos[sport]
                elif dport in protos:
                    proto = protos[dport]

            # 校验和
            crc = None
            if IP in packet:
                ip = packet[IP]
                ip_chksum = ip.chksum
                ip.chksum = None
                ip_check = IP(raw(ip)).chksum
                ip.chksum = ip_chksum
                # print(ip_chksum, "计算出的IP首部校验和：", ip_check)

                if TCP in packet:
                    tcp = packet[TCP]
                    tcp_chksum = tcp.chksum
                    tcp.chksum = None
                    tcp_check = TCP(raw(tcp)).chksum
                    tcp.chksum = tcp_chksum
                    # print(tcp_chksum, "计算出的TCP检验和：", tcp_check)

                    if ip_check == ip_chksum and tcp_check == tcp_chksum:
                        crc = ("IP与TCP的校验和检查通过\r\nIP的校验和为：{chksum_ip}\r\nTCP的检验和为：{chksum_tcp}"
                               .format(chksum_ip=ip_chksum, chksum_tcp=tcp_chksum))
                    else:
                        crc = "IP或TCP的校验和出错"
                elif UDP in packet:
                    udp = packet[UDP]
                    udp_chksum = udp.chksum
                    udp.chksum = None

                    udp_check = UDP(raw(udp)).chksum
                    udp.chksum = udp_chksum

                    if ip_check == ip_chksum and udp_check == udp_chksum:
                        crc = ("IP与UDP的校验和检查通过\r\nIP的校验和为：{chksum_ip}\r\nUDP的检验和为：{chksum_udp}"
                               .format(chksum_ip=ip_chksum, chksum_udp=udp_chksum))
                    else:
                        crc = "IP或UDP的校验和出错"

            packet_info["time"] = packet_time
            packet_info["src"] = src
            packet_info["dst"] = dst
            packet_info["proto"] = proto
            packet_info["len"] = str(len(packet))
            packet_info["info"] = packet.summary()
            packet_info["packet"] = packet
            packet_info["crc"] = crc
            self.packet_captured.emit(packet_info)

    def should_stop(self, packet):
        return not self.sniffing

    def pause_sniffing(self):
        self.paused = True  # 标记为暂停

    def resume_sniffing(self):
        self.paused = False  # 取消暂停
