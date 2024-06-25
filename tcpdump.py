import os
import json
import subprocess
import time
import datetime
import re
import random
import psutil
import requests

highestpkts = 10000


def get_ip():
    ip = subprocess.getoutput(r"ip -4 addr show ens3 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'")
    return ip


def get_bytes(t, iface='ens3'):
    with open(f'/sys/class/net/{iface}/statistics/{t}_bytes', 'r') as f:
        data = f.read()
    return int(data)


def get_network_stats(ethernet='ens3'):
    tx_prev = get_bytes('tx', ethernet)
    rx_prev = get_bytes('rx', ethernet)
    time.sleep(1)
    tx_after = get_bytes('tx', ethernet)
    rx_after = get_bytes('rx', ethernet)
    recieved_bytes = rx_after - rx_prev
    transmitted_bytes = tx_after - tx_prev
    mbits_received = recieved_bytes / (102400 * 8)
    mbits_transmitted = transmitted_bytes / (102400 * 8)
    mbits_received = round(mbits_received, 2)
    mbits_transmitted = round(mbits_transmitted, 2)
    return mbits_received, mbits_transmitted


def get_pps(ethernet='ens3'):
    old_ps = subprocess.check_output(f"grep {ethernet} /proc/net/dev | cut -d : -f2 | awk '{{print $2}}'", shell=True)
    old_ps2 = int(old_ps.decode('utf8').rstrip())
    time.sleep(1)
    new_ps = subprocess.check_output(f'grep {ethernet} /proc/net/dev | cut -d : -f2 | awk \'{{print $2}}\'', shell=True)
    new_ps2 = int(new_ps.decode('utf8').rstrip())
    pps = new_ps2 - old_ps2
    return pps


def get_connected_users():
    try:
        with open("/etc/openvpn/server/openvpn-status.log", 'r') as f:
            output = f.read()
        connected_users = re.findall(r'CLIENT_LIST(.*?)END', output, re.DOTALL)
        num_connected_users = len(connected_users)
        if num_connected_users == 0:
            connected_users_str = "No users Found"
        else:
            connected_users_str = ' '.join(connected_users)
    except FileNotFoundError:
        num_connected_users = 0
        connected_users_str = "OpenVPN not installed"
    return num_connected_users, connected_users_str
    

def analyze_pcap(txts, lmaos221342):
    os.makedirs(f'{txts}/pcap', exist_ok=True)
    os.system(f'tcpdump -i ens3 -n -s0 -c 5000 -w {txts}/pcap/analyze.{lmaos221342}.pcap')
    gangsta = subprocess.getoutput(f"tshark -r {txts}/pcap/analyze.{lmaos221342}.pcap -T fields -E header=y -e ip.proto -e tcp.flags -e udp.srcport -e tcp.srcport -e data | sed '/^[[:space:]]*$/d'")
    os.makedirs(f'{txts}/dst', exist_ok=True)
    os.makedirs(f'{txts}/src', exist_ok=True)
    os.system(f"tshark -r {txts}/pcap/analyze.{lmaos221342}.pcap -T fields -E header=y -e tcp.srcport | head -2 | sed 's/ *//g' | tail -n +2 | sed 's/[a-z]//g' | sed 's/[A-Z]//g' > {txts}/dst/test.txt")
    os.system(f"tshark -r {txts}/pcap/analyze.{lmaos221342}.pcap -T fields -E header=y -e tcp.dstport | head -2 | sed 's/ *//g' | tail -n +2 | sed 's/[a-z]//g' | sed 's/[A-Z]//g' > {txts}/src/test2.txt")
    return gangsta


def get_attack_type(capture_file):
    attack_types = {
        "[UDP]": "17		",
        "[ICMP]": "1		",
        "[ICMP Dest Unreachable]": "1,17		",
        "[IPv4/Fragmented]": "4		",
        "[GRE]": "47		",
        "[IPX]": "111		",
        "[AH]": "51		",
        "[ESP]": "50		",
        "[OpenVPN Reflection]": "17		1194",
        "[VSE Flood/1]": "17		27015",
        "[RRSIG DNS Query Reflection]": "002e0001",
        "[ANY DNS Query Reflection]": "00ff0001",
        "[NTP Reflection]": "17		123",
        "[Chargen Reflection]": "17		19",
        "[MDNS Reflection]": "17		5353",
        "[BitTorrent Reflection]": "17		6881",
        "[CLDAP Reflection]": "17		389",
        "[STUN Reflection]": "17		3478",
        "[MSSQL Reflection]": "17		1434",
        "[SNMP Reflection]": "17		161",
        "[WSD Reflection]": "17		3702",
        "[DTLS Reflection]": "17		443		40",
        "[OpenAFS Reflection]": "17		7001",
        "[ARD Reflection]": "17		3283",
        "[BFD Reflection]": "17		3784",
        "[SSDP Reflection]": "17		1900",
        "[ArmA Reflection/1]": "17		2302",
        "[ArmA Reflection/2]": "17		2303",
        "[vxWorks Reflection]": "17		17185",
        "[Plex Reflection]": "17		32414",
        "[TeamSpeak Reflection]": "17		9987",
        "[Lantronix Reflection]": "17		30718",
        "[DVR IP Reflection]": "17		37810",
        "[Jenkins Reflection]": "17		33848",
        "[Citrix Reflection]": "17		1604",
        "[NAT-PMP Reflection]": "008000",
        "[Memcache Reflection]": "17		11211",
        "[NetBIOS Reflection]": "17		137",
        "[SIP Reflection]": "17		5060",
        "[Digiman Reflection]": "17		2362",
        "[Crestron Reflection]": "17		41794",
        "[CoAP Reflection]": "17		5683",
        "[BACnet Reflection]": "17		47808",
        "[FiveM Reflection]": "17		30120",
        "[Modbus Reflection]": "17		502",
        "[QOTD Reflection]": "17		17",
        "[ISAKMP Reflection]": "17		500",
        "[XDMCP Reflection]": "17		177",
        "[IPMI Reflection]": "17		623",
        "[Apple serialnumberd Reflection]": "17		626",
        "[Flood of 0x00]": "0000000000000000000",
        "[OVH-RAPE]": "fefefefe",
        "[Flood of HTTPS]": "6		443",
        "[Flood of HTTP]": "6		80",
        "[Ooakla Speedtest]": "0x00000010		8080",
        "[TCP FIN]": "0x00000001",
        "[TCP SYN]": "0x00000002",
        "[TCP PSH]": "0x00000008",
        "[TCP URG]": "0x00000020",
        "[TCP RST]": "0x00000004",
        "[TCP ACK]": "0x00000010"
    }
    attack_type = ''
    for occurrences in attack_types:
        number = capture_file.count(attack_types[occurrences])
        if number > 1000:
            percentage = 100 * float(number) / float(7400)
            attack_type += f" {occurrences} [({str(round(percentage, 2))}%)]"
    if not attack_type:
        attack_type = "Undetermined"
    return attack_type


def get_dst_port(txts, lmaos221342):
    try:
        with open(f"{txts}/dst/test.txt", 'r') as f:
            dst_port = f.read().strip()
    except FileNotFoundError:
        dst_port = "Randomized"
    return dst_port


def send_webhook(attack_type, dst_port, num_connected_users, connected_users_str, mbits_received, mbits_transmitted, pps):
    webhook_url = "https://discord.com/api/webhooks/1211441381965434920/suE2czuRhnhIz41e_kquJs1kTVjvmGx6NMVi5gCWVjJEPMmzOlZ5r1RK-S2tZIGcmesq"  # Insert your webhook URL here
    cpu_usage = psutil.cpu_percent()
    uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime_str = str(uptime).split(".")[0]

    payload = {
        "embeds": [
            {
                "title": "DDoS Protection",
                "description": "We have detected a possible DDoS attack on our infrastructure we have saved the attack for further inspection.",
                "url": "https://globalsecurelayer.com/",
                "color": "16770815",
                "timestamp": str(datetime.datetime.utcnow()),
                "author": {
                  "icon_url": "https://cdn.discordapp.com/attachments/1217930104479547543/1217932627877560413/gsl-letter-logo-design-in-illustration-logo-calligraphy-designs-for-logo-poster-invitation-etc-vector-removebg-preview.png",
                   "name": "JPVPN",

                },
                "footer": {
                  "text": "We have detected a possible DDoS attack. We have saved it for the future incase of truncation.",
                  "icon_url": "https://ezgif.com/images/loadcat.gif",
                },
                "thumbnail": {
                    "url": "https://image.kkday.com/image/get/s1.kkday.com/product_9558/20170809103130_G6CbP/jpg"
                },
                "fields": [
                    {
                        "name": ":globe_with_meridians: Location:",
                        "value": "Tokyo, JP",
                        "inline": False
                    },
                    {
                        "name": ":zap: Load:",
                        "value": f"{cpu_usage}%",
                        "inline": False
                    },
                    {
                        "name": ":arrow_down: Incoming",
                        "value": f"{mbits_received} MB/s",
                        "inline": False
                    },
                    {
                        "name": ":arrow_up: Outgoing",
                        "value": f"{mbits_transmitted} MB/s",
                        "inline": False
                    },
                    {
                        "name": ":robot: Attack Type",
                        "value": attack_type,
                        "inline": False
                    },
                    {
                        "name": ":warning: Attacked IP",
                        "value": "194.195.89.29",
                        "inline": False
                    },
                    {
                        "name": ":mag_right: Attacked Port:",
                        "value": dst_port,
                        "inline": False
                    },
                    {
                        "name": ":satellite_orbital: ISP:",
                        "value": "GSL Networks LTD",
                        "inline": False
                    },
                    {
                        "name": ":gear: Uptime:",
                        "value": uptime_str,
                        "inline": False
                    },
                    {
                        "name": ":busts_in_silhouette: Users Conneceted",
                        "value": str(num_connected_users),
                        "inline": False
                    },
                    {
                        "name": ":bust_in_silhouette: Users Online",
                        "value": connected_users_str,
                        "inline": False
                    }
                ],
                
            }
        ]
    }

    header_data = {'content-type': 'application/json'}
    response = requests.post(webhook_url, json.dumps(payload), headers=header_data)
    print(response.text)


def main():
    txts = "/home/status/tcpdump"
    ip = get_ip()
    num_captures = subprocess.getoutput(f"ls {txts}/pcap/ | wc -l")

    while True:
        lmaos221342 = random.randrange(1, 30000)
        mbits_received, mbits_transmitted = get_network_stats()
        pps = get_pps()
        print(f"PPS: {pps}")

        if pps > highestpkts:
            capture_file = analyze_pcap(txts, lmaos221342)
            attack_type = get_attack_type(capture_file)
            dst_port = get_dst_port(txts, lmaos221342)
            num_connected_users, connected_users_str = get_connected_users()
            send_webhook(attack_type, dst_port, num_connected_users, connected_users_str, mbits_received, mbits_transmitted, pps)
            print(f"Sleeping for 60 seconds")
            time.sleep(60)


if __name__ == "__main__":
    main()