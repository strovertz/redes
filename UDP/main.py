from scapy.all import *
from scapy.all import UDP, rdpcap
import matplotlib.pyplot as plt


def attack_detect(attack_threshold, protocols):
    return {proto: info["count"] > attack_threshold for proto, info in protocols.items()}

def cria_grafico(protocols, attack_detected):
    protocol_names = list(protocols.keys())
    protocol_counts = [info["count"] for info in protocols.values()]

    plt.figure(figsize=(10, 6))

    colors = ['blue' if not attack_detected[proto] else 'red' for proto in protocol_names]

    plt.bar(protocol_names, protocol_counts, color=colors)
    plt.xlabel('Protocolos')
    plt.ylabel('Número de Pacotes')
    plt.title('Contagem de Pacotes por Protocolo')

    legend_labels = [plt.Rectangle((0,0),1,1, color=color) for color in ['blue', 'red']]
    plt.legend(legend_labels, ['Normal', 'Possível Ataque'])

    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    plt.show()

def count_specific_protocols(filename):
    protocols = {
        "DNS": {"port": 53, "count": 0},
        "HTTP": {"port": 80, "count": 0},
        "SSDP": {"port": 1900, "count": 0},
        "CLDAP": {"port": 389, "count": 0},
        "NTP": {"port": 123, "count": 0},
        "ICMP": {"port": 1, "count": 0},
        "SYSLOG": {"port": 514, "count": 0}
    }

    packets = rdpcap(filename)
    print(len(packets))
    for packet in packets:
        if packet.haslayer(UDP):
            udp_packet = packet[UDP]
            for proto, info in protocols.items():
                if udp_packet.dport == info["port"] or udp_packet.sport == info["port"]:
                    protocols[proto]["count"] += 1
                    break

    attack_detected = attack_detect(attack_threshold = (len(packets) * 0.4), protocols = protocols)

    print("Protocolos específicos:")
    for proto, info in protocols.items():
        print(f"{proto}: {info['count']} pacotes")

    cria_grafico(protocols, attack_detected)

if __name__ == "__main__":
    pcap_file = "udp.pcap"
    count_specific_protocols(pcap_file)
