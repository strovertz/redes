import math
import json
from collections import defaultdict
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
import geocoder
from scapy.all import rdpcap, DNS, DNSQR, DNSRR

#Função para calcular a distancia a partir da lat e long
def haversine(lat1, lon1, lat2=-29.711035, lon2=-53.716464):
    # Converter graus para radianos
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])

    # Diferenças das coordenadas
    dlat = lat2 - lat1
    dlon = lon2 - lon1

    # Fórmula de Haversine
    a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    # Raio da Terra em km
    r = 6371
    
    # Distância
    distance = c * r
    return distance

def escolhe_ip(ips):
    min_distance = float('inf')
    chosen_ip = None

    for ip in ips:
        myAddress = get_location(ip)
        if len(myAddress) == 2:
            distance = haversine(myAddress[0], myAddress[1])
            if distance < min_distance:
                min_distance = distance
                chosen_ip = ip

    return chosen_ip

# Função para obter a localização do IP usando ip-api
def get_location(ip):
    myAddress = []
    try:
        url = f"http://ip-api.com/json/{ip}"
        request = urlopen(url, timeout=5)
        data = request.read().decode()
        data = json.loads(data)
        
        if data['status'] == "success":
            myAddress.append(data['lat'])
            myAddress.append(data['lon'])
    except (URLError, HTTPError, TimeoutError) as e:
        print(f"Erro ao obter a localização do IP {ip}: {e}")

    return myAddress

# Função alternativa para obter a localização do IP usando geocoder
def get_location2(ip):
    try:
        g = geocoder.ip(ip)
        return g.latlng if g.latlng else []
    except:
        return []

def process_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    domain_requests = defaultdict(lambda: {'count': 0, 'responses': [], 'response_count': 0})
    processed_domains = set()

    for packet in packets:
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # DNS query
            domain = packet.getlayer(DNSQR).qname.decode('utf-8').strip('.')
            if domain not in processed_domains:
                processed_domains.add(domain)

            domain_requests[domain]['count'] += 1

        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 1:  # DNS response
            domain = packet.getlayer(DNS).qd.qname.decode('utf-8').strip('.')
            if domain in domain_requests and not domain_requests[domain]['responses']:
                response_ips = []
                for i in range(packet.getlayer(DNS).ancount):
                    if packet.getlayer(DNS).an[i].type in [1, 28]:  # 1 for A (IPv4), 28 for AAAA (IPv6)
                        response_ips.append((packet.getlayer(DNS).an[i].rdata, packet.getlayer(DNS).an[i].ttl, packet.getlayer(DNS).an[i].rrname.decode('utf-8').strip('.'), packet.getlayer(DNS).ancount))

                chosen_ip = escolhe_ip([ip for ip, ttl, rrname, ancount in response_ips])
                if chosen_ip:
                    for ip, ttl, rrname, ancount in response_ips:
                        if ip == chosen_ip:
                            domain_requests[domain]['responses'].append({'ip': chosen_ip, 'ttl': ttl, 'rrname': rrname, 'response_count': ancount})

    return domain_requests

def save_to_json(data, filename):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)

if __name__ == "__main__":
    pcap_file = "dns.pcap"
    output_file = "site/dns_data.json"
    dns_data = process_pcap(pcap_file)
    save_to_json(dns_data, output_file)
    print(f"Data saved to {output_file}")
