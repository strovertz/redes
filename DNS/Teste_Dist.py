import math

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

x = haversine(-22.9243143,-43.4710816)
y = haversine(36.8708175,139.9938155)

print(f"Rio = {x} + Japao = {y}")