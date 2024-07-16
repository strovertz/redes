# # # # Import # # # #
# This Python file uses the following encoding: utf-8
from scapy.all import rdpcap, ARP
import pandas as pd
import matplotlib.pyplot as plt

packets = rdpcap('arp.pcap')

arp_packets = [pkt for pkt in packets if ARP in pkt]
arp_degratis = [pkt for pkt in arp_packets if pkt.op == 2 and not pkt.haslayer('ARP Request')]
arp_requested_packets = [pkt for pkt in arp_packets if (pkt.op == 1) or (pkt.op == 2 and pkt.haslayer(ARP))]

print(f"Total de ARP: {len(arp_packets)}")

data = {
    'timestamp': [],
    'op': [],
    'src_mac': [],
    'src_ip': [],
    'dst_mac': [],
    'dst_ip': []
}

for pkt in arp_packets:
    data['timestamp'].append(float(pkt.time))
    data['op'].append(pkt.op)
    data['src_mac'].append(pkt.hwsrc)
    data['src_ip'].append(pkt.psrc)
    data['dst_mac'].append(pkt.hwdst)
    data['dst_ip'].append(pkt.pdst)

df = pd.DataFrame(data)

print('Pacotes ARP Gratuitos: ', len(arp_degratis))
if len(arp_degratis) > (len(arp_packets) * 0.5): print('Sua rede esta sofrento um ATAQUE')
num_arp_requested = len(arp_requested_packets)

data = {
    'Tipo': ['ARP Gratuitos', 'ARP Solicitados'],
    'Quantidade': [len(arp_degratis), num_arp_requested]
}
df2 = pd.DataFrame(data)


plt.figure(figsize=(10, 6))
plt.bar(df2['Tipo'], df2['Quantidade'], color=['blue', 'green'])
plt.title('Comparação entre ARP Gratuitos e ARP Solicitados')
plt.xlabel('Tipo de Pacote ARP')
plt.ylabel('Quantidade')
plt.tight_layout()
plt.show()

df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')

time_elapsed = df['timestamp'].iloc[-1] - df['timestamp'].iloc[0]

print(df.info())
print("Tempo decorrido entre o primeiro e o ultimo timestamp:", time_elapsed)

plt.figure(figsize=(12, 6))
plt.plot(df['timestamp'], range(len(df)), marker='o', linestyle='', markersize=5)
plt.title('Distribuição Temporal dos Pacotes ARP')
plt.xlabel('Tempo')
plt.ylabel('Índice do Pacote ARP')
plt.tight_layout()
plt.show()
