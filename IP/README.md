﻿# packet-location-analyzer


## Sobre

O programa captura pacotes de rede, filtrando o IP de destino (sua rede) e alguns IPs de origem (packet-location-analyzer/src/trabalho1.pcapng) através da localização IP e cria uma marcação em uma página HTML gerada usando folium.

## Uso

Clone este repositório e navegue até a pasta 'src':
```bash
git clone https://github.com/strovertz/packet-location-analyzer.
```
```
cd packet-location-analyzer/src
```
Execute o comando abaixo para capturar pacotes e gerar seu mapa:
```
python main.py
```

## Dados Disponíveis
```json
'User IP': '20.0.28.08'
'CountryName': 'Brazil'
'UsageType': 'Data Center/Web Hosting/Transit'
'Isp': 'Example Corporation | Internet Service Provider'
'Domain': 'microsoft.com | IP Domain'
'isTor': 'False'
'abuseConfidenceScore': 0
```
#### abuseConfidenceScore |
 ```
 AbuseConfidenceScore é nossa avaliação calculada sobre o quão abusivo é o IP com base nos usuários que o reportaram.
 ```
#### Valores possíveis para UsageType:
```
- Commercial
- Organization
- Government
- Military
- University/College/School
- Library
- Content Delivery Network
- Fixed Line ISP
- Mobile ISP
- Data Center/Web Hosting/Transit
- Search Engine Spider
- Reserved
```

##### Folium Tile:
Earth At Night
```python
tiles="https://demo.ldproxy.net/earthatnight/tiles/WebMercatorQuad/{z}/{y}/{x}?f=jpeg", attr='EarthAtNight'
```


 <b>AbuseIPDB</b>: https://docs.abuseipdb.com/#check-endpoint

<b>Gleison</b>: github.com/strovertz
<b><br>Felipe Sanfelice</b>:
<b><br>Giovanni Roman</b>:
<b><br>Francisco Ribas</b>:
