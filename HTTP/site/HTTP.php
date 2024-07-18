<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dados HTTP Capturados</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            padding: 20px;
        }
        h2 {
            margin-bottom: 10px;
        }
        .host-container {
            margin-bottom: 20px;
        }
        .request {
            margin-bottom: 10px;
            padding: 10px;
            background-color: #f0f0f0;
            border: 1px solid #ccc;
        }
        .request-details {
            margin-top: 5px;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <h1>Dados Capturados de Requisições HTTP</h1>

    <?php
    // Caminho para o arquivo JSON gerado pelo Python
    $json_file = 'caminho/para/seu/output.json';

    // Lê o conteúdo do arquivo JSON
    $json_data = file_get_contents($json_file);

    // Decodifica o JSON para um array associativo
    $data = json_decode($json_data, true);

    // Verifica se há dados para exibir
    if ($data) {
        // Itera sobre os hosts
        foreach ($data as $host => $host_data) {
            echo '<div class="host-container">';
            echo "<h2>Host: $host</h2>";
            echo "<p>Total de Requisições: {$host_data['count']}</p>";

            // Itera sobre as requisições de cada host
            foreach ($host_data['requests'] as $request) {
                echo '<div class="request">';
                echo "<p>URI: {$request['uri']}</p>";
                echo "<p>IP de Origem: {$request['source_ip']}</p>";
                echo "<p>URL Completa: {$request['full_url']}</p>";
                echo "<p>Tamanho do File Data: {$request['file_data_size']} bytes</p>";
                echo '</div>';
            }

            echo '</div>';
        }
    } else {
        echo '<p>Nenhum dado encontrado.</p>';
    }
    ?>

</body>
</html>