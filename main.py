import json
import os
import ipaddress as ipa
from tabulate import tabulate
import csv

input_txt_file = 'log.txt'
output_json_file = 'log.json'
output_risk_csv_file = 'report/risk_report.csv'
############################################
private1 = ipa.ip_network('10.0.0.0/16')
private2 = ipa.ip_network('10.50.0.0/16')
vpn = ipa.ip_network('192.168.0.0/16')
public1 = ipa.IPv4Address('241.223.148.36')
public2 = ipa.IPv4Address('26.66.77.16')
public3 = ipa.IPv4Address('60.142.8.92')


def create_json_file(data, file):
    if os.path.exists(file):
        os.remove(file)
    out_file = open(file, "w")
    json.dump(data, out_file, indent=4)
    out_file.close()


def convert_to_json(file):
    json_list = []
    fields = ['srcaddr', 'dstaddr', 'port', 'action']
    with open(file) as fh:
        next(fh)
        for line in fh:
            description = list(line.strip().split(None, 4))
            i = 0
            entry = {}
            while i < len(fields):
                entry[fields[i]] = description[i]
                i = i + 1
            json_list.append(entry)
    create_json_file(json_list, output_json_file)


def ports_actions_filters(file):
    accept_list=[]
    f = open(file)
    data = json.load(f)
    for i in data:
        if i['port'] != '80' and i['port'] != '443': 
            # print(i)
            if i['action'] == 'ACCEPT':
                accept_list.append(i)
    f.close()         
    return accept_list


def filter_allow_address(data):
    risk_list=[]
    for i in data:
        srcaddr = ipa.IPv4Address(i['srcaddr'])
        if (srcaddr not in private1 and srcaddr not in private2 and srcaddr not in vpn) and (srcaddr != public1 and srcaddr != public2 and srcaddr !=  public3) and (srcaddr.is_private == False):
            risk_list.append(i)
    return risk_list


def generate_report(data, output_file):
    port_SSH = 0
    port_SQL = 0
    port_NetBIOS = 0
    port_RPC = 0
    port_FTP = 0
    port_Telnet = 0
    if os.path.exists(output_file):
        os.remove(output_file)
    f = open(output_file, 'w', newline='')
    csv_writer = csv.writer(f)
    csv_writer.writerow(["srcaddr", "dstaddr", "port", "action"])
    for i in data:
            if i['port'] == '22':
                port_SSH += 1
                csv_writer.writerow(i.values())
            elif i['port'] == '1433' or i['port'] == '1434':
                port_SQL += 1
                csv_writer.writerow(i.values())
            elif i['port'] == '137' or i['port'] == '138' or i['port'] == '139' :
                port_NetBIOS += 1
                csv_writer.writerow(i.values())
            elif i['port'] == '135':
                port_RPC += 1
                csv_writer.writerow(i.values())
            elif i['port'] == '21':
                port_FTP += 1
                csv_writer.writerow(i.values())
            elif i['port'] == '23':
                port_Telnet += 1
                csv_writer.writerow(i.values())
    f.close()
    print()
    print('Listagem das requisições recebidas com o estado de ACCEPT, contendo como origem endereços IP públicos não conhecidos:\n')
    print('------------------------')
    print(tabulate([['SSH', port_SSH], ['FTP', port_FTP], ['Telnet', port_Telnet], ['SQL', port_SQL], ['NetBIOS', port_NetBIOS], ['RCP', port_RPC]], headers=['Service', 'Risk Count']))
    print('------------------------\n')
    print('Foi gerado o arquivo "risk_report.csv" com todas conexões desconhecidas baseadas nos serviços acima\n')
    

def main():
    convert_to_json(input_txt_file)
    ports_actions_filter = ports_actions_filters(output_json_file)
    filtered = filter_allow_address(ports_actions_filter)
    generate_report(filtered, output_risk_csv_file)

    
if __name__ == "__main__":
    main()
