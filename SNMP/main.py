from scapy.all import Ether, SNMP, rdpcap

def process_snmp_packets(pkts):
    snmp_get_count = 0
    snmp_set_count = 0

    for pkt in pkts:
        if SNMP in pkt:
            pdu_type = pkt[SNMP].PDU.__class__.__name__
            if pdu_type == "SNMPget":
                snmp_get_count += 1
                print(f"SNMP GET request found: Community={pkt[SNMP].community.decode('utf-8')}")
                # Aqui você pode processar mais detalhes do pacote SNMP GET
            elif pdu_type == "SNMPset":
                snmp_set_count += 1
                print(f"SNMP SET request found: Community={pkt[SNMP].community.decode('utf-8')}")
                # Aqui você pode processar mais detalhes do pacote SNMP SET

    print(f"Total de SNMP GET requests encontrados: {snmp_get_count}")
    print(f"Total de SNMP SET requests encontrados: {snmp_set_count}")

def main():
    pcap_file = "snmp.pcap"
    packets = rdpcap(pcap_file)

    protocol_counts = {}
    for pkt in packets:
        print(pkt)
        if pkt.haslayer(Ether):
            ether_type = pkt[Ether].type
            if ether_type in protocol_counts:
                protocol_counts[ether_type] += 1
            else:
                protocol_counts[ether_type] = 1

    print("Protocol Packet Counts:")
    for protocol, count in protocol_counts.items():
        print(f"{protocol}: {count} packets")

    process_snmp_packets(packets)

if __name__ == "__main__":
    main()
