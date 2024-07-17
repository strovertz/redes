from scapy.all import *
import matplotlib.pyplot as plt

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

            # Check for SYN
            if flags & 0x02:  # SYN
                syn_count += 1
                if (src_ip, dst_ip) not in handshake_complete:
                    handshake_complete[(src_ip, dst_ip)] = {'SYN': False, 'SYN-ACK': False, 'ACK': False}
                handshake_complete[(src_ip, dst_ip)]['SYN'] = True

            # Check for SYN-ACK
            elif flags & 0x12:  # SYN-ACK
                if (dst_ip, src_ip) in handshake_complete:
                    handshake_complete[(dst_ip, src_ip)]['SYN-ACK'] = True

            # Check for ACK
            elif flags & 0x10:  # ACK
                ack_count += 1
                if (src_ip, dst_ip) in handshake_complete and handshake_complete[(src_ip, dst_ip)]['SYN-ACK']:
                    handshake_complete[(src_ip, dst_ip)]['ACK'] = True

    syn_ack_ratio = syn_count / ack_count if ack_count > 0 else None

    print(f"Total de pacotes TCP SYN: {syn_count}")
    print(f"Total de pacotes TCP ACK: {ack_count}")
    print(f"Taxa de SYN/ACK: {syn_ack_ratio}")

    incomplete_handshakes = [(src_ip, dst_ip) for (src_ip, dst_ip), states in handshake_complete.items() if not states['ACK']]

    if incomplete_handshakes:
        print("Sinais de possível SYN flood detectados!")
        print("Conexões incompletas (falta ACK final):")
        #for src_ip, dst_ip in incomplete_handshakes:
        #    print(f"{src_ip} -> {dst_ip}")
    else:
        print("Não foram encontrados sinais de SYN flood.")

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
