# ARP

## Detalhamento

Inicialmente faz uma comparação entre os pacotes que foram realmente requisitados e os que estão imundando a rede com gratuitous ARP

Em um ataque ARP "De grátis" (redes é um dos poucos locais onde nem injeção na testa aceitamos de gratis), o atacante explora esse comportamento legítimo para realizar ARP Spoofing. Aqui está um exemplo de como isso pode ser feito:

- Enviando ARP Gratuitous Falsos:

O atacante envia pacotes ARP gratuitos que anunciam que o endereço IP do gateway (roteador) está associado ao endereço MAC do atacante.
Esses pacotes são enviados para todos os dispositivos na rede local.
Enganando Dispositivos:

Quando os dispositivos na rede recebem esses pacotes ARP gratuitos, eles atualizam suas tabelas ARP para mapear o endereço IP do gateway para o endereço MAC do atacante.

- Interception:

Agora, qualquer tráfego destinado ao gateway é enviado para o atacante.
O atacante pode interceptar, modificar ou simplesmente observar esse tráfego antes de encaminhá-lo para o gateway real.

## Em segundo plano, exibe uma linha do tempo, para termos noção do tempo entre um pacote e outro.