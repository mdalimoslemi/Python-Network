from flask import Flask, render_template, request
import scapy.all as scapy
import threading
import time
from scapy.layers.inet import IP, TCP, UDP
from sklearn.ensemble import IsolationForest
import numpy as np
from pysnmp.hlapi import *

app = Flask(__name__)

packets = []
classified_packets = {'TCP': [], 'UDP': []}
ai_analysis_results = []
network_status = {}

def capture_packets():
    def process_packet(packet):
        packets.append(packet)
        if packet.haslayer(TCP):
            classified_packets['TCP'].append(packet)
        elif packet.haslayer(UDP):
            classified_packets['UDP'].append(packet)

    scapy.sniff(prn=process_packet, store=False)

def analyze_traffic():
    while True:
        if len(packets) > 0:
            packet_features = []
            for packet in packets:
                packet_features.append([len(packet), packet.time])
            packets.clear()

            if len(packet_features) > 0:
                model = IsolationForest(contamination=0.1)
                predictions = model.fit_predict(packet_features)
                ai_analysis_results.clear()
                ai_analysis_results.extend(predictions)
        time.sleep(10)

def monitor_network_status():
    while True:
        network_status.clear()
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(),
            CommunityData('public', mpModel=0),
            UdpTransportTarget(('localhost', 161)),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),
            lexicographicMode=False
        ):
            if errorIndication:
                network_status['error'] = str(errorIndication)
            elif errorStatus:
                network_status['error'] = '%s at %s' % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?')
            else:
                for varBind in varBinds:
                    network_status[str(varBind[0])] = str(varBind[1])
        time.sleep(10)

@app.route('/')
def index():
    return render_template('index.html', classified_packets=classified_packets, ai_analysis_results=ai_analysis_results, network_status=network_status)

@app.route('/filter', methods=['POST'])
def filter_packets():
    ip_address = request.form.get('ip_address')
    filtered_packets = {'TCP': [], 'UDP': []}
    for packet in classified_packets['TCP']:
        if packet[IP].src == ip_address or packet[IP].dst == ip_address:
            filtered_packets['TCP'].append(packet)
    for packet in classified_packets['UDP']:
        if packet[IP].src == ip_address or packet[IP].dst == ip_address:
            filtered_packets['UDP'].append(packet)
    return render_template('index.html', classified_packets=filtered_packets, ai_analysis_results=ai_analysis_results, network_status=network_status)

if __name__ == '__main__':
    threading.Thread(target=capture_packets).start()
    threading.Thread(target=analyze_traffic).start()
    threading.Thread(target=monitor_network_status).start()
    app.run(debug=True)
