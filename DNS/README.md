#Processador de Respostas DNS
Este projeto consiste em um script Python que processa pacotes DNS de um arquivo PCAP, extrai informações relevantes e as salva em um arquivo JSON. Adicionalmente, um script PHP lê este arquivo JSON e exibe os dados em um formato de tabela HTML estruturada.

##Script Python
O script Python executa as seguintes tarefas:

###Processamento do Arquivo PCAP:

Lê pacotes DNS de um arquivo PCAP fornecido. Para cada consulta e resposta DNS, extrai informações relevantes, como o nome do domínio, endereços IP, TTL (tempo de vida), RRName (nome do registro de recurso) e o número de respostas.
Recupera a localização geográfica (latitude e longitude) de um endereço IP usando o serviço ip-api.com ou um método alternativo utilizando a biblioteca geocoder. Calcula a distância entre dois pontos geográficos, dadas suas latitudes e longitudes, usando a fórmula de Haversine.Escolhe o endereço IP com a menor distância geográfica até um local predefinido a partir de uma lista de endereços IP.
Armazena as informações em um formato estruturado.

###Saída JSON:

Salva os dados processados em um arquivo JSON.
Estrutura do JSON
O arquivo JSON de saída tem a seguinte estrutura:
´´´
json
Copiar código
{
    "www.example.com": {
        "count": 20,
        "responses": [
            {
                "ip": "192.0.2.1",
                "ttl": 114,
                "rrname": "example.rrname.com",
                "response_count": 2
            }
        ],
    }
}

´´´
##Script PHP
O script PHP lê o arquivo JSON e exibe os dados em uma tabela HTML estruturada.
