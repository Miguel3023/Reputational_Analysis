#!/usr/bin/python3

import hashlib
from virus_total_apis import PublicApi
import requests
import json
import pdb
import signal
import sys
import re
from countries import get_countries
#Variabes Globales

API_KEY = '' #Cambiar valor al correspondiente

api = PublicApi(API_KEY)

countries = get_countries()

def leaving(sig, frame):

    print("\nSaliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, leaving)

def get_analysis():

    global IP

    IP = input("¿Cuál es la IP a Analizar?\n\n")

    print("================================================================")
    print("========= Análisis Reputacional  =========")
    print("================================================================")


    url = f'https://www.virustotal.com/api/v3/ip_addresses/{IP}'

    header_apikey = {'x-apikey':API_KEY}

    request = requests.get(url, headers=header_apikey)
    print(f"\nAnálisis reputacional a IP: {IP}\n")

    print("---------------------------VirusTotal------------------------------\n")

    return request.text


#Principal Functions


def principal_data():

    parsed_data = json.loads(get_analysis())
    
    data_value = parsed_data["data"]
    return data_value

def principal_attributes(data_value):

    if "attributes" in data_value:

        data_attributes = data_value["attributes"]
    
    return data_attributes


def parser_ip_and_country(ip, country):


    if "id" in ip:

        value_id = ip["id"]

        #print(f"\nAnálisis reputacional a IP: {value_id}\n")       

    country = country["country"]
    key = list(countries.keys())
    
    if country in key:
        country_name = countries[country]

        print(f"Origen: {country} ({country_name})")

def parser_last_analysis_stats(data_attributes):


    if "last_analysis_stats" in data_attributes:

        data_stats = data_attributes["last_analysis_stats"]
        
        print(f'Maliciosas: {data_stats["malicious"]}',
              f'\nSospechosas: {data_stats["suspicious"]}',
              f'\nNo maliciosas: {data_stats["undetected"]}',
              f'\nInofensivas: {data_stats["harmless"]}',
              f'\nTiempo de espera: {data_stats["timeout"]}/seg',
              )
        if data_stats["malicious"] > 3:

            print("Conclusión: IP catalogada como MALICIOSA")
        else: 
            print("Conclusión: La IP no es maliciosa")

    maliciosas = data_stats["malicious"]
    sospechosas = data_stats["suspicious"]
    no_maliciosas = data_stats["undetected"]
    inofensivas = data_stats["harmless"]
    tiempo_espera = data_stats["timeout"]

    total = maliciosas + sospechosas + no_maliciosas + inofensivas + tiempo_espera
    total2 = maliciosas + sospechosas

    print(f"Total Score: {total2}/{total}")

    if "network" in data_attributes:
        network_info = data_attributes["network"]
        print(f"El segmento de red es: {network_info}")

def parser_last_analysis_results(data_attributes):

    if "last_analysis_results" in data_attributes:

        principal_data = data_attributes["last_analysis_results"]
        print("Security vendors' analysis:")
        
        for clave, valor in principal_data.items():
            if valor["category"] == "malicious":

                result_malicious = valor["result"]
                result_name = valor["engine_name"]
                result_category = valor["category"]

                print(f"\n{result_name}: \n\tResultado: {result_malicious}\n\tCategoría: {result_category}")
                


            if valor["category"] == "suspicious":
                
                result_suspicious = valor["result"]
                result_name2 = valor["engine_name"] 
                result_category2 = valor["category"]

                print(f"\n{result_name2}: \n\tResultado:{result_suspicious}\n\tCategoría: {result_category2}")


def abuseIPDB():

    print("\n---------------------------AbuseIPDB-------------------------------\n")

    abuse_ip_url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'key':'', #Cambiar valor al correspondiente
        'Accept': 'application/json'
    }

    params = {

        'ipAddress': IP,
        'maxAgeInDays': 90,
        'verbose': True
    }


    response = requests.get(abuse_ip_url, headers=headers, params=params)

    if response.status_code == 200:

        data = response.json()
        Ip_ipdb = (data['data']['ipAddress'])
        print(f"IP: {Ip_ipdb}")
        
        is_white_list = (data['data']['isWhitelisted'])
        
        if is_white_list is not None:

            print(f"Está en lista blanca: {is_white_list}")

        if data['data']['abuseConfidenceScore'] > 50:
            abuse_score = (data['data']['abuseConfidenceScore'])
            print(f"Porcentaje malicioso: {abuse_score}")
            print("Conclusión: IP catalogada como MALICIOSA")
        else:
            abuse_score = (data['data']['abuseConfidenceScore'])
            print(f"Porcentaje malicioso: {abuse_score}")
            print("Conclusión: No se considera maliciosa")

        usage_type = (data['data']['usageType'])

        if usage_type is not None:

            print(f"Usage Type: {usage_type}")

        isp = (data['data']['isp'])

        print(f"ISP: {isp}")
   
        domain = (data['data']['domain'])

        print(f"Dominio: {domain}")

        hostnames = (data['data']['hostnames'])

        print(f"Hostnames: {hostnames}")

        isTor = (data['data']['isTor'])

        print(f"Se emplea TOR: {isTor}")

        countryName = (data['data']['countryName'])

        print(f"Origen: {countryName}")

        totalReports = (data['data']['totalReports'])

        print(f"Total de reportes: {totalReports}")

    else:
        print("Error en obtener los datos")



def IPVoid():

    print("\n---------------------------IPVoid----------------------------------\n\n")

    API_KEY = ""

    url_void = f"https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={API_KEY}&ip={IP}"

    petition = requests.get(url_void)

    data = petition.json()

    if petition.status_code == 200:

        ip = (data['data']['report']['ip'])

        print(f"IP: {ip}")


        country_name = data['data']['report']['information']['country_name']
        
        print(f"Origen: {country_name}")
        
        is_tor = data['data']['report']['anonymity']['is_tor']

        print(f"Emplea TOR: {is_tor}")

        city_name = data['data']['report']['information']['city_name']
    
        print(f"Ciudad: {city_name}")

        isp = data['data']['report']['information']['isp']
    
        print(f"ISP: {isp}")

        reverse_dns = data['data']['report']['information']['reverse_dns']
        
        print(f"Reverse DNS: {reverse_dns}")

        detections = (data['data']['report']['blacklists']['detections'])

        if detections > 4:

            print(f"Detecciones: {detections}")
            print("Conclusión: IP catalogada como MALICOSA")
        else:
            print(f"Detecciones: {detections}")
            print("Conclusión: No se considera maliciosa")


def main(ip, data_attributes):
 
    parser_ip_and_country(ip,data_attributes)
    parser_last_analysis_stats(data_attributes)
    #parser_last_analysis_results(data_attributes)
    abuseIPDB()
    IPVoid()

if __name__=='__main__':

    data_value = principal_data()
    data_attributes = principal_attributes(data_value)
    main(data_value, data_attributes)
