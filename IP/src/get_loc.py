from urllib.request import urlopen
from geopy.geocoders import Nominatim
from geopy.distance import geodesic
import requests
import json
import geocoder

def get_infos(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": '90',
        "verbose": True
    }
    headers = {
        "Key": 'f9f3e24bb9562dc30649e1a694ba4fff9ee0e5801f89ded8c1b70872902c83d350ec4ec70eb28859',
        "Accept": "application/json"
    }
    response = requests.get(url, params=params, headers=headers)
    infos = json.loads(response.text)
    return infos

def process_ips(ips):
    myAddress = []
    for i in ips:
        myAddress.append(get_location(i))
        print('\n')
        print(i)
    return myAddress

#tem 2 funcoes pq existe um limite de requisições que podem ser feitas por dia em cada API
#Então caso atinja o limite, basta utilizar a outra função
def get_location(ip):

    myAddress = []

    if ip:
        #url da api
        url = f"http://ip-api.com/json/{ip}"
        request = urlopen(url)
        data = request.read().decode()

        data = eval(data)
    if data['status'] != "success":
        return myAddress

    myAddress.append(data['lat'])
    myAddress.append(data['lon'])

    return myAddress

def get_location2(ip):

    f = geocoder.ip(ip)

    myAddress = f.latlng

    return myAddress
