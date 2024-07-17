import folium

coord_geo = []
dicionarios = []
dicionario = {}

def set_markup(mapa, location, ip, infos):
    popupe = "User IP: " + str(ip) + "\n | CountryName: " + str(infos['data']['countryName']) + "\n | UsageType: " + str(infos['data']['usageType']) + '\nIsp: ' + str(infos['data']['isp']) + '\n | Domain: ' + str(infos['data']['domain']) + '\n\n | isTor: ' + str(infos['data']['isTor']) + '\n | abuseConfidenceScore:' + str(infos['data']['abuseConfidenceScore'])
    folium.Marker([location[0], location[1]], popup = popupe, icon=folium.Icon(color='lightblue')).add_to(mapa)
    return mapa

def create_map(my_location):
    #Retorna um mapa com a "nossa localização"
    mapa = folium.Map(location=[my_location[0], my_location[1]], zoom_start=1, tiles="https://demo.ldproxy.net/earthatnight/tiles/WebMercatorQuad/{z}/{y}/{x}?f=jpeg", attr='EarthAtNight')
    #folium.TileLayer("StamenTerrain").add_to(mapa) # a intencao era adicionar uma overlay de terreno, mas parece q essa chamada ta com problema na lib
    folium.TileLayer(show=False, overlay=True).add_to(mapa)

    folium.LayerControl().add_to(mapa)

    popupe = "User IP: Strovertz" + "\n" + "Nome: Gleison Pires"
    folium.Marker([my_location[0], my_location[1]], popup = popupe, icon=folium.Icon(color='lightgreen', icon='home')).add_to(mapa)
    return mapa
