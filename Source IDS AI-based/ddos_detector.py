import numpy as np
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import logging
from datetime import datetime, timezone, UTC
from tensorflow.keras.models import load_model
import os
import json
from scapy.layers.l2 import Ether, ARP
import subprocess
import pytz

class DDoSDetector:
    def __init__(self, model_path):
        self.flows = defaultdict(self._init_flow)
        self.model = load_model(model_path)
        
        logging.basicConfig(
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO,
            handlers=[logging.FileHandler('/etc/ids/log/stdout.log'), logging.StreamHandler()]
        )

    def _init_flow(self):
        return {
            'start_time': None,
            'last_active': None,
            'src_ips': set(),
            'dst_ip': None,
            'packets': [],  # Lưu chi tiết từng gói tin
            'flags': defaultdict(int),
            'protocol': None,
            'header_lengths': [],
            'app_protos': defaultdict(int)
        }

    def start(self, interface=None):
        logging.info(f"🚀 Starting DDoS detector on interface {interface or 'default'}")
        filter_str = "not net 10.81.89.0/24"
        sniff(prn=self.process_packet, store=False, iface=interface, filter=filter_str)

    def process_packet(self, packet):
        try:
            if packet.haslayer(ARP):
                flow_key = (packet[ARP].pdst, 0x0806)
                flow = self.flows[flow_key]
                if flow['start_time'] is None:
                    flow.update({
                        'start_time': packet.time,
                        'last_active': packet.time,
                        'src_ips': {packet[ARP].psrc},
                        'dst_ip': packet[ARP].pdst,
                        'protocol': 0x0806,
                        'packets': [{
                            'src_ip': packet[ARP].psrc,
                            'dst_ip': packet[ARP].pdst,
                            'timestamp': packet.time,
                            'packet_size': len(packet),
                            'protocol': 'ARP'
                        }],
                        'flags': defaultdict(int),
                        'header_lengths': [0],
                        'app_protos': defaultdict(int)
                    })
                else:
                    flow['src_ips'].add(packet[ARP].psrc)
                    flow['last_active'] = packet.time
                    flow['packets'].append({
                        'src_ip': packet[ARP].psrc,
                        'dst_ip': packet[ARP].pdst,
                        'timestamp': packet.time,
                        'packet_size': len(packet),
                        'protocol': 'ARP'
                    })
                    flow['header_lengths'].append(0)
                if self._is_flow_complete(packet, flow):
                    if len(flow['packets']) >= 100 and (packet.time - flow['start_time']) < 1.0:
                        features = self._extract_features(flow, packet)
                        del self.flows[flow_key]
                        self._predict_and_alert(features)
                    else:
                        del self.flows[flow_key]  # Xóa flow nếu không đạt ngưỡng thời gian
                        self._init_new_flow(self.flows[flow_key], packet, packet[ARP])  # Bắt đầu lại
            elif packet.haslayer(IP):
                ip = packet[IP]
                flow_key = (ip.dst, ip.proto)
                flow = self.flows[flow_key]
                if flow['start_time'] is None:
                    self._init_new_flow(flow, packet, ip)
                self._update_flow_stats(flow, packet)
                if self._is_flow_complete(packet, flow):
                    if len(flow['packets']) >= 100 and (packet.time - flow['start_time']) < 1.0:
                        features = self._extract_features(flow, packet)
                        del self.flows[flow_key]
                        self._predict_and_alert(features)
                    else:
                        del self.flows[flow_key]  # Xóa flow nếu không đạt ngưỡng thời gian
                        self._init_new_flow(self.flows[flow_key], packet, ip)  # Bắt đầu lại
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def _init_new_flow(self, flow, packet, ip_layer):
        flow.update({
            'start_time': packet.time,
            'last_active': packet.time,
            'src_ips': {ip_layer.src if hasattr(ip_layer, 'src') else packet[ARP].psrc},
            'dst_ip': ip_layer.dst if hasattr(ip_layer, 'dst') else packet[ARP].pdst,
            'protocol': ip_layer.proto if hasattr(ip_layer, 'proto') else 0x0806,
            'packets': []
        })

    def _update_flow_stats(self, flow, packet):
        ip = packet[IP]
        flow['src_ips'].add(ip.src)
        flow['last_active'] = packet.time
        packet_info = {
            'src_ip': ip.src,
            'dst_ip': ip.dst,
            'timestamp': packet.time,
            'packet_size': len(packet),
            'protocol': 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else 'IP',
            'header_length': ip.ihl * 4
        }
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
            packet_info['src_port'] = layer.sport
            packet_info['dst_port'] = layer.dport
            ports = [layer.dport, layer.sport]
            if 80 in ports or 8080 in ports: flow['app_protos']['HTTP'] += 1
            if 443 in ports: flow['app_protos']['HTTPS'] += 1
            if 53 in ports: flow['app_protos']['DNS'] += 1
            if 23 in ports: flow['app_protos']['Telnet'] += 1
            if 25 in ports: flow['app_protos']['SMTP'] += 1
            if 22 in ports: flow['app_protos']['SSH'] += 1
            if 6667 in ports: flow['app_protos']['IRC'] += 1
            if 67 in ports or 68 in ports: flow['app_protos']['DHCP'] += 1
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flow['flags']['S'] += 1 if tcp.flags & 0x02 else 0
            flow['flags']['A'] += 1 if tcp.flags & 0x10 else 0
            flow['flags']['F'] += 1 if tcp.flags & 0x01 else 0
            flow['flags']['R'] += 1 if tcp.flags & 0x04 else 0
            flow['flags']['P'] += 1 if tcp.flags & 0x08 else 0
            flow['flags']['U'] += 1 if tcp.flags & 0x20 else 0
            flow['flags']['ECE'] += 1 if tcp.flags & 0x40 else 0
            flow['flags']['CWR'] += 1 if tcp.flags & 0x80 else 0
        flow['packets'].append(packet_info)
        flow['header_lengths'].append(ip.ihl * 4)

    def _is_flow_complete(self, packet, flow):
        # Kiểm tra nếu đã đủ 100 gói tin
        return len(flow['packets']) >= 100

    def _extract_features(self, flow, packet):
        timestamps = [p['timestamp'] for p in flow['packets']]
        packet_sizes = [p['packet_size'] for p in flow['packets']]
        flow_duration = float(timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0)
        packet_count = int(len(timestamps))
        rate = float(packet_count / flow_duration if flow_duration > 0 else 0)
        iats = np.diff(timestamps) if len(timestamps) > 1 else np.array([0])
        iat_mean = float(np.mean(iats) if iats.size > 0 else 0)

        is_tcp = int(1 if flow['protocol'] == 6 else 0)
        is_udp = int(1 if flow['protocol'] == 17 else 0)
        is_icmp = int(1 if flow['protocol'] == 1 else 0)
        total_bytes = int(sum(packet_sizes))
        avg_packet_size = float(np.mean(packet_sizes) if packet_sizes else 0)
        std_packet_size = float(np.std(packet_sizes) if packet_sizes else 0)
        min_packet_size = int(min(packet_sizes) if packet_sizes else 0)
        max_packet_size = int(max(packet_sizes) if packet_sizes else 0)
        header_lengths = flow['header_lengths']
        header_length_mean = float(np.mean(header_lengths) if header_lengths else 0)
        covariance = float(np.cov(packet_sizes, timestamps)[0][1] if len(timestamps) > 1 else 0)
        variance = float(np.var(packet_sizes) if packet_sizes else 0)
        radius = float(np.sqrt(np.sum(np.diff(packet_sizes)**2)) if len(packet_sizes) > 1 else 0)
        weight = float(total_bytes / flow_duration if flow_duration > 0 else 0)

        features = {
            'flow_duration': flow_duration,
            'Header_Length': header_length_mean,
            'Protocol Type': int(flow['protocol']),
            'Duration': flow_duration,
            'Rate': rate,
            'Srate': float((flow['flags']['A'] + flow['flags']['F']) / flow_duration if flow_duration > 0 else 0),
            'Drate': float((flow['flags']['A'] + flow['flags']['F']) / flow_duration if flow_duration > 0 else 0),
            'fin_flag_number': int(flow['flags']['F']),
            'syn_flag_number': int(flow['flags']['S']),
            'rst_flag_number': int(flow['flags']['R']),
            'psh_flag_number': int(flow['flags']['P']),
            'ack_flag_number': int(flow['flags']['A']),
            'ece_flag_number': int(flow['flags']['ECE']),
            'cwr_flag_number': int(flow['flags']['CWR']),
            'ack_count': int(flow['flags']['A']),
            'syn_count': int(flow['flags']['S']),
            'fin_count': int(flow['flags']['F']),
            'urg_count': int(flow['flags']['U']),
            'rst_count': int(flow['flags']['R']),
            'HTTP': int(1 if flow['app_protos']['HTTP'] > 0 else 0),
            'HTTPS': int(1 if flow['app_protos']['HTTPS'] > 0 else 0),
            'DNS': int(1 if flow['app_protos']['DNS'] > 0 else 0),
            'Telnet': int(1 if flow['app_protos']['Telnet'] > 0 else 0),
            'SMTP': int(1 if flow['app_protos']['SMTP'] > 0 else 0),
            'SSH': int(1 if flow['app_protos']['SSH'] > 0 else 0),
            'IRC': int(1 if flow['app_protos']['IRC'] > 0 else 0),
            'TCP': is_tcp,
            'UDP': is_udp,
            'DHCP': int(1 if flow['app_protos']['DHCP'] > 0 else 0),
            'ARP': int(1 if flow['protocol'] == 0x0806 else 0),
            'ICMP': is_icmp,
            'IPv': int(packet[IP].version if packet.haslayer(IP) else 0),
            'LLC': int(1 if packet.haslayer(Ether) else 0),
            'Tot sum': total_bytes,
            'Min': min_packet_size,
            'Max': max_packet_size,
            'AVG': avg_packet_size,
            'Std': std_packet_size,
            'Tot size': total_bytes,
            'IAT': iat_mean,
            'Number': packet_count,
            'Magnitue': float(np.sqrt(packet_count)),
            'Radius': radius,
            'Covariance': covariance,
            'Variance': variance,
            'Weight': weight,
            'src_ips': list(flow['src_ips']),
            'dst_ip': flow['dst_ip'],
            'packets': flow['packets']
        }

        features['urg_flag_number'] = int(flow['flags']['U'])

        feature_df = pd.DataFrame([{
            'flow_duration': features['flow_duration'],
            'Header_Length': features['Header_Length'],
            'Protocol Type': features['Protocol Type'],
            'Duration': features['Duration'],
            'Rate': features['Rate'],
            'Srate': features['Srate'],
            'Drate': features['Drate'],
            'fin_flag_number': features['fin_flag_number'],
            'syn_flag_number': features['syn_flag_number'],
            'rst_flag_number': features['rst_flag_number'],
            'psh_flag_number': features['psh_flag_number'],
            'ack_flag_number': features['ack_flag_number'],
            'ece_flag_number': features['ece_flag_number'],
            'cwr_flag_number': features['cwr_flag_number'],
            'ack_count': features['ack_count'],
            'syn_count': features['syn_count'],
            'fin_count': features['fin_count'],
            'urg_count': features['urg_count'],
            'rst_count': features['rst_count'],
            'HTTP': features['HTTP'],
            'HTTPS': features['HTTPS'],
            'DNS': features['DNS'],
            'Telnet': features['Telnet'],
            'SMTP': features['SMTP'],
            'SSH': features['SSH'],
            'IRC': features['IRC'],
            'TCP': features['TCP'],
            'UDP': features['UDP'],
            'DHCP': features['DHCP'],
            'ARP': features['ARP'],
            'ICMP': features['ICMP'],
            'IPv': features['IPv'],
            'LLC': features['LLC'],
            'Tot sum': features['Tot sum'],
            'Min': features['Min'],
            'Max': features['Max'],
            'AVG': features['AVG'],
            'Std': features['Std'],
            'Tot size': features['Tot size'],
            'IAT': features['IAT'],
            'Number': features['Number'],
            'Magnitue': features['Magnitue'],
            'Radius': features['Radius'],
            'Covariance': features['Covariance'],
            'Variance': features['Variance'],
            'Weight': features['Weight']
        }])

        features['feature_df'] = feature_df
        return features

    def _predict_and_alert(self, features):
        prediction = self.model.predict(features['feature_df'], verbose=0)
        probability = float(prediction[0][0] if prediction.shape[-1] == 1 else prediction[0][1])
        if probability > 0.5:
            self._alert(features, probability)
            self._log_attack(features, probability)

    def _alert(self, features, probability):
        protocol = 'Unknown'
        if features['TCP'] == 1:
            protocol = 'TCP'
        elif features['UDP'] == 1:
            protocol = 'UDP'
        elif features['ICMP'] == 1:
            protocol = 'ICMP'
        elif features['ARP'] == 1:
            protocol = 'ARP'

        app_protocol = 'Unknown'
        if features['HTTP'] == 1:
            app_protocol = 'HTTP'
        elif features['HTTPS'] == 1:
            app_protocol = 'HTTPS'
        elif features['DNS'] == 1:
            app_protocol = 'DNS'
        elif features['Telnet'] == 1:
            app_protocol = 'Telnet'
        elif features['SMTP'] == 1:
            app_protocol = 'SMTP'
        elif features['SSH'] == 1:
            app_protocol = 'SSH'
        elif features['IRC'] == 1:
            app_protocol = 'IRC'
        elif features['DHCP'] == 1:
            app_protocol = 'DHCP'

        dst_ports = [p.get('dst_port') for p in features['packets'] if 'dst_port' in p]
        dst_port = dst_ports[0] if dst_ports else 'N/A'

        flags = {
            'SYN': features['syn_flag_number'],
            'ACK': features['ack_flag_number'],
            'FIN': features['fin_flag_number'],
            'RST': features['rst_flag_number'],
            'PSH': features['psh_flag_number'],
            'URG': features['urg_flag_number']
        }
        flags_str = ', '.join([f"{k}={v}" for k, v in flags.items() if v > 0])
        src_ip_display = features['src_ips'][0] if len(features['src_ips']) == 1 else f"Multiple sources ({len(features['src_ips'])} IPs)"
        
        alert_msg = f"""
        🚨 DDoS ATTACK DETECTED 🚨
        Source: {src_ip_display}
        Target: {features['dst_ip']}
        Flow Duration: {features['flow_duration']:.6f}s
        Header Length: {features['Header_Length']}
        Min packet size: {features['Min']}
        Max packet size: {features['Max']}
        AVG packet size: {features['AVG']}
        Packet Count: {features['Number']}
        Protocol: {protocol}
        Destination Port: {dst_port}
        Application Protocol: {app_protocol}
        Flags: {flags_str if flags_str else 'None'}
        Probability: {probability:.4f}
        """
        logging.warning(alert_msg)
        
        # Tóm tắt flow
        unique_src_ips = list(set(p['src_ip'] for p in features['packets']))
        unique_src_ports = list(set(p.get('src_port') for p in features['packets'] if 'src_port' in p))
        unique_dst_ports = list(set(p.get('dst_port') for p in features['packets'] if 'dst_port' in p))
        tz = pytz.timezone('Asia/Ho_Chi_Minh')
        current_time = datetime.now(tz)
        timestampnow = current_time.isoformat()        
        log_entry = {
            '@timestamp': timestampnow,
            'event_type': 'ddos_attack',
            'alert': f"DDoS ATTACK DETECTED_{protocol} FLOOD",
            'flow_summary': {
                'dst_ip': features['dst_ip'],
                'unique_src_ips': unique_src_ips,
                'src_ips_count': len(unique_src_ips),
                'unique_src_ports': unique_src_ports,
                'src_ports_count': len(unique_src_ports),
                'unique_dst_ports': unique_dst_ports,
                'dst_ports_count': len(unique_dst_ports),
                'packet_count': features['Number'],
                'flow_duration': features['flow_duration'],
                'header_length': features['Header_Length'],
                'min_packet_size': features['Min'],
                'max_packet_size': features['Max'],
                'avg_packet_size': features['AVG'],
                'protocol': protocol,
                'application_protocol': app_protocol,
                'probability': probability,
                'flags': flags
            }
        }
        with open('/etc/ids/log/ddos_attacks.json', 'a') as f:
            json.dump(log_entry, f)
            f.write('\n')
    
    def _log_attack(self, features, probability):
        log_entry = {
            'flow_duration': features['flow_duration'],
            'Header_Length': features['Header_Length'],
            'Protocol Type': features['Protocol Type'],
            'Duration': features['Duration'],
            'Rate': features['Rate'],
            'Srate': features['Srate'],
            'Drate': features['Drate'],
            'fin_flag_number': features['fin_flag_number'],
            'syn_flag_number': features['syn_flag_number'],
            'rst_flag_number': features['rst_flag_number'],
            'psh_flag_number': features['psh_flag_number'],
            'ack_flag_number': features['ack_flag_number'],
            'ece_flag_number': features['ece_flag_number'],
            'cwr_flag_number': features['cwr_flag_number'],
            'ack_count': features['ack_count'],
            'syn_count': features['syn_count'],
            'fin_count': features['fin_count'],
            'urg_count': features['urg_count'],
            'rst_count': features['rst_count'],
            'HTTP': features['HTTP'],
            'HTTPS': features['HTTPS'],
            'DNS': features['DNS'],
            'Telnet': features['Telnet'],
            'SMTP': features['SMTP'],
            'SSH': features['SSH'],
            'IRC': features['IRC'],
            'TCP': features['TCP'],
            'UDP': features['UDP'],
            'DHCP': features['DHCP'],
            'ARP': features['ARP'],
            'ICMP': features['ICMP'],
            'IPv': features['IPv'],
            'LLC': features['LLC'],
            'Tot sum': features['Tot sum'],
            'Min': features['Min'],
            'Max': features['Max'],
            'AVG': features['AVG'],
            'Std': features['Std'],
            'Tot size': features['Tot size'],
            'IAT': features['IAT'],
            'Number': features['Number'],
            'Magnitue': features['Magnitue'],
            'Radius': features['Radius'],
            'Covariance': features['Covariance'],
            'Variance': features['Variance'],
            'Weight': features['Weight'],
            'label': 1 if probability > 0.5 else 0  # Sử dụng probability để xác định label
        }
        log_df = pd.DataFrame([log_entry])
        log_df.to_csv('/etc/ids/share/local/ddos_attacks.csv', mode='a', header=not os.path.exists('/etc/ids/share/local/ddos_attacks.csv'), index=False)

    def _block_ip(self, ip):
        pass

if __name__ == "__main__":
    detector = DDoSDetector('/etc/ids/share/model/Detection-model.keras')
    detector.start(interface='ens37')
