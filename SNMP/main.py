import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import rdpcap, SNMP

def extract_data(packets):
    snmp_data = []

    for packet in packets:
        if packet.haslayer(SNMP):
            for varbind in packet[SNMP].PDU.varbindlist:
                snmp_info = {
                    'timestamp': float(packet.time),
                    'source_ip': packet[1].src,
                    'destination_ip': packet[1].dst,
                    'snmp_version': packet[SNMP].version,
                    'snmp_community': packet[SNMP].community.val,
                    'snmp_oid': varbind.oid.val,
                    'snmp_value': varbind.value.val
                }
                snmp_data.append(snmp_info)
    return snmp_data    

def oids_accessed(df):
    plt.figure(figsize=(10, 6))
    oid_counts = df['snmp_oid'].value_counts().head(10)
    oid_counts.plot(kind='bar')
    plt.title('Top 10 OIDs Accessed')
    plt.xlabel('OID')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.show()

def response_time(df):
    df['response_time'] = df.groupby(['source_ip', 'destination_ip'])['timestamp'].diff().dt.total_seconds()
    plt.figure(figsize=(10, 6))
    plt.hist(df['response_time'].dropna(), bins=50)
    plt.title('SNMP Response Times')
    plt.xlabel('Response Time (seconds)')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.show()

def comm_strings(df):
    plt.figure(figsize=(10, 6))
    community_counts = df['snmp_community'].value_counts()
    community_counts.plot(kind='bar')
    plt.title('SNMP Community Strings')
    plt.xlabel('Community String')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.show()

def heat_map(df):
    src_dst_pairs = df.groupby(['source_ip', 'destination_ip']).size().reset_index(name='counts')
    src_dst_pairs_pivot = src_dst_pairs.pivot_table(index='source_ip', columns='destination_ip', values='counts', fill_value=0)
    plt.figure(figsize=(12, 8))
    plt.title('Source-Destination Pairs Heatmap')
    plt.xlabel('Destination IP')
    plt.ylabel('Source IP')
    plt.imshow(src_dst_pairs_pivot, cmap='hot', interpolation='nearest')
    plt.colorbar(label='Number of Packets')
    plt.xticks(range(len(src_dst_pairs_pivot.columns)), src_dst_pairs_pivot.columns, rotation=90)
    plt.yticks(range(len(src_dst_pairs_pivot.index)), src_dst_pairs_pivot.index)
    plt.tight_layout()
    plt.show()

def main():
    pcap_file = 'snmp.pcap'
    packets = rdpcap(pcap_file)
    df = pd.DataFrame(extract_data(packets))
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')

    print(f'Total SNMP packets: {len(df)}')
    print(df)
    oids_accessed(df)
    response_time(df)
    comm_strings(df)
    heat_map(df)

if __name__ == '__main__':
    main()