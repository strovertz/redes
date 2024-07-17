<?php
    // Incluindo o cabeçalho da página
    include_once 'includes/header.php';
    // Incluindo o arquivo de mensagem
    include_once 'includes/mensagem.php';

    // Lendo o arquivo JSON
    $jsonFile = 'dns_data.json';
    $jsonData = file_get_contents($jsonFile);
    $dnsData = json_decode($jsonData, true);
?>
<div class="row">
    <div class="col s10 m10 push-m1 "> 
        <h3 class="light">DNS Responses</h3>
        <!--Tabela de DNS-->
        <table class="striped">
            <thead>
                <tr>
                    <th>Dominio</th>
                    <th>Contagem de Querys</th>
                    <th>IP</th>
                    <th>TTL</th>
                    <th>RRName</th>
                    <th>Contagem de Respostas</th>
                </tr>
            </thead>
            <tbody>
                <?php if (!empty($dnsData)): ?>
                    <?php foreach ($dnsData as $domain => $data): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($domain); ?></td>
                            <td><?php echo htmlspecialchars($data['count']); ?></td>
                            <?php if (!empty($data['responses'])): ?>
                                <?php foreach ($data['responses'] as $response): ?>
                                    <td><?php echo htmlspecialchars($response['ip']); ?></td>
                                    <td>- <?php echo htmlspecialchars($response['ttl']); ?></td>
                                    <td><?php echo htmlspecialchars($response['rrname']); ?></td>
                                    <td><?php echo htmlspecialchars($response['response_count']); ?></td>
                                </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <td colspan="4">No responses</td>
                            </tr>
                            <?php endif; ?>
                    <?php endforeach; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="6">No data available</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
<?php
    // Incluindo o rodapé da página
    include_once 'includes/footer.php'; 
?>
