import pyshark
import json

# Função para buscar a resposta correspondente para uma requisição
def find_response_data(cap, request_frame_number):
    for packet in cap:
        try:
            http_layer = packet.http
            if hasattr(http_layer, 'response_to') and int(http_layer.response_to) == request_frame_number:
                if hasattr(http_layer, 'file_data'):
                    return len(http_layer.file_data.binary_value)
        except AttributeError:
            continue
    return 0

# Função para extrair informações dos pacotes HTTP
def extract_http_info(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='http')
    http_info = []
    for packet in cap:
        try:
            http_layer = packet.http
            ip_src = packet.ip.src
            host = http_layer.host
            uri = http_layer.request_uri
            full_url = f"http://{host}{uri}"
            
            file_data_size = find_response_data(cap, int(packet.frame_info.number))

            http_info.append({
                'source_ip': ip_src,
                'host': host,
                'uri': uri,
                'full_url': full_url,
                'file_data_size': file_data_size
            })
        except AttributeError:
            pass
    cap.close()
    return http_info

# Função para organizar os dados no formato desejado
def organize_data(http_info):
    data = {}
    for entry in http_info:
        host = entry['host']
        source_ip = entry['source_ip']
        uri = entry['uri']
        full_url = entry['full_url']
        file_data_size = entry['file_data_size']

        if host not in data:
            data[host] = {
                'requests': [],
                'count': 0
            }
        data[host]['requests'].append({
            'uri': uri,
            'source_ip': source_ip,
            'full_url': full_url,
            'file_data_size': file_data_size
        })
        data[host]['count'] += 1
    return data

# Função para salvar os dados em um arquivo JSON
def save_to_json(data, output_file):
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4)

# Caminho para o arquivo pcap
pcap_file = 'http_witp_jpegs.pcap'
# Caminho para o arquivo JSON de saída
output_file = 'site/output.json'

# Extrai as informações HTTP dos pacotes
http_info = extract_http_info(pcap_file)
# Organiza os dados no formato desejado
organized_data = organize_data(http_info)
# Salva os dados em um arquivo JSON
save_to_json(organized_data, output_file)

print(f"Dados salvos em {output_file}")
