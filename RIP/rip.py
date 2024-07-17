import json
from scapy.all import rdpcap, RIP, IP
import networkx as nx
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import messagebox

def get_edges(rip_packets):
    G = nx.DiGraph()
    for pkt in rip_packets:
        rip_pkt = pkt.getlayer(RIP)
        if rip_pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            addr = rip_pkt.addr
            mask = rip_pkt.mask
            next_hop = rip_pkt.nextHop
            metric = rip_pkt.metric
            if next_hop != "0.0.0.0":
                G.add_edge(src_ip, next_hop, metric=metric)
    return G

def plot_graph(G):
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G)
    edge_colors = []
    edge_labels = {}
    for u, v, data in G.edges(data=True):
        metric = data['metric']
        if metric == 16:
            edge_colors.append('red')
            edge_labels[(u, v)] = f'{metric} (unreachable)'
        elif metric <= 5:
            edge_colors.append('green')
            edge_labels[(u, v)] = str(metric)
        elif metric <= 10:
            edge_colors.append('yellow')
            edge_labels[(u, v)] = str(metric)
        else:
            edge_colors.append('blue')
            edge_labels[(u, v)] = str(metric)

    nx.draw(G, pos, with_labels=True, node_size=2000, node_color='skyblue', font_size=10, font_weight='bold', edge_color=edge_colors, width=2.0, arrows=True)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8, label_pos=0.3)

    plt.title('Grafo de Rotas RIP')
    plt.show()

def main():
    pcap_file = 'RIP.pcap'
    packets = rdpcap(pcap_file)
    rip_packets = [packet for packet in packets if RIP in packet]
    G = get_edges(rip_packets)
    if G.edges:
        plot_graph(G)
    else:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Sem Pacotes RIP Válidos", "Não foram encontrados pacotes RIP válidos para exibir rotas.")
        root.destroy()

if __name__ == '__main__':
    main()
