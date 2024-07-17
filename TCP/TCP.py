from scapy.all import *
import matplotlib.pyplot as plt
from gen import insert_locs
import pydivert
import requests
import thread6
import os
import webbrowser
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from collections import Counter
from get_loc import *
from map import *

@thread6.threaded()
def package_load():
    for i in range(100):
        res = requests.get('http://ec2-3-95-214-97.compute-1.amazonaws.com:8080/health')
        print(res.text)
    exit()

def capture_package():
    lista = []; lista2 = []; ips = []; bit = 0
    prefix = ['172', '192', '10.', '127', '255', 'fe8']
    with pydivert.WinDivert() as w:
        for packet in w:
            if packet.direction and packet.src_addr not in ips and packet.src_addr[:3] not in prefix: ips.append(packet.src_addr)
            print(packet)
            w.send(packet)
            if bit == 300: break
            bit+=1
    return ips

def read_pcap(file_path):
    pcap_ips = []
    prefix = ['172', '192', '10.', '127', '255', 'fe8']
    for (packet_data, packet_metadata,) in RawPcapReader(file_path):
        packet_eth = Ether(packet_data)
        packet_ip = packet_eth[IP]
        if packet_ip.proto != 6:
           continue
        if packet_ip.src[:3] not in prefix and packet_ip.src not in pcap_ips: pcap_ips.append(packet_ip.src)
    return pcap_ips

def insert_locs(ips):
    mapa = create_map([-29.6894956, -53.811126])
    address = process_ips(ips)
    print(address)
    j = 0
    for i in address:
        if len(i) > 1: infos = get_infos(ips[j]); mapa = set_markup(mapa, i, ips[j], infos); print(f'Lat,Lon de ip \'{j}\': {i}')
        j+=1
    if len(address) > 0: mapa = set_markup(mapa,[len(address)-2,len(address)-1], ips[len(ips)-1], get_infos(ips[len(ips)-1]))
    mapa.save("map/my_map1.html")
    print('Mapa Salvo em ../map/')
    filename = 'file:///'+os.getcwd()+'/' + 'map/my_map1.html'
    webbrowser.open_new_tab(filename)

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    syn_count = 0
    ack_count = 0
    handshake_complete = {}

    for packet in packets:
        if TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            flags = packet[TCP].flags

            if flags & 0x02 and not flags & 0x10:
                syn_count += 1
                if (src_ip, dst_ip) not in handshake_complete:
                    handshake_complete[(src_ip, dst_ip)] = {'SYN': False, 'SYN-ACK': False, 'ACK': False}
                handshake_complete[(src_ip, dst_ip)]['SYN'] = True

            elif flags & 0x12:
                if (dst_ip, src_ip) in handshake_complete:
                    handshake_complete[(dst_ip, src_ip)]['SYN-ACK'] = True

            elif flags & 0x10 and not flags & 0x02:
                ack_count += 1
                if (src_ip, dst_ip) in handshake_complete and handshake_complete[(src_ip, dst_ip)]['SYN-ACK']:
                    handshake_complete[(src_ip, dst_ip)]['ACK'] = True

    syn_ack_ratio = syn_count / ack_count if ack_count > 0 else None

    print(f"Total de pacotes TCP SYN: {syn_count}")
    print(f"Total de pacotes TCP ACK: {ack_count}")
    print(f"Taxa de SYN/ACK: {syn_ack_ratio}")

    incomplete_handshakes = [(src_ip, dst_ip) for (src_ip, dst_ip), states in handshake_complete.items() if not states['ACK']]

    src_ips = []
    dst_ips = []
    if incomplete_handshakes:
        print("Sinais de possível SYN flood detectados!")
        print("Conexões incompletas (falta ACK final):")
        for src_ip, dst_ip in incomplete_handshakes:
            print(f"{src_ip} -> {dst_ip}")
            if src_ip: src_ips.append(src_ip)
    else:
        print("Não foram encontrados sinais de SYN flood.")

    insert_locs(src_ips)

    labels = ['Pacotes SYN', 'Pacotes ACK']
    sizes = [syn_count, ack_count]
    colors = ['#ff9999', '#66b3ff']
    explode = (0.1, 0)

    plt.figure(figsize=(8, 5))
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', shadow=True, startangle=140)
    plt.axis('equal')
    plt.title('Análise de Pacotes TCP')
    plt.show()

pcap_file = "tcp.pcap"
analyze_pcap(pcap_file)
