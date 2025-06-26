from elasticsearch import Elasticsearch
from paramiko import SSHClient, AutoAddPolicy
import time

# Kết nối Elasticsearch
es = Elasticsearch(['http://10.81.89.131:9200'])  # Cập nhật URL từ log mới

# Kết nối SSH đến core switch/router
ssh = SSHClient()
ssh.set_missing_host_key_policy(AutoAddPolicy())
ssh.connect('10.81.89.128', username='thna', password='th261104')  # Cập nhật thông tin SSH

# Danh sách rule.name chỉ alert, không chặn
ALERT_ONLY_RULES = [
    "UnknownMimeTypeDiscovery::Unknown_Mime_Type_Detected",
    "Only observed 0 TCP ACKs and was expecting at least 1."
]

def block_ip(src_ip, dst_ip, attack_type, port=None, proto= "tcp", source="Unknown"):
    """Thêm rule iptables để chặn IP qua SSH."""
    # Kiểm tra rule đã tồn tại trong chain FORWARD
    #check_cmd = f"sudo iptables -L FORWARD -n | grep {src_ip} | grep {dst_ip}"
    if port:
        check_cmd = f"sudo iptables -S FORWARD | grep -E '^-A.*-s {src_ip}.*-d {dst_ip}.*--dport {port}'"
    else:
        check_cmd = f"sudo iptables -S FORWARD | grep -E '^-A.*-s {src_ip}.*-d {dst_ip}'"
    stdin, stdout, stderr = ssh.exec_command(check_cmd)
    output = stdout.read().decode()
    if not output.strip():
        # Tạo quy tắc iptables
        if port:
            iptables_cmd = f"sudo iptables -I FORWARD 1 -s {src_ip} -d {dst_ip} -p {proto} --dport {port} -j DROP"
        else:
            iptables_cmd = f"sudo iptables -I FORWARD 1 -s {src_ip} -d {dst_ip} -j DROP"
        stdin, stdout, stderr = ssh.exec_command(iptables_cmd)
        error = stderr.read().decode()
        if error:
            print(f"[{timestamp}] Error adding iptables rule for {src_ip} to {dst_ip} (port {port}): {error}")
        else:
            print(f"[{timestamp}] Blocked IP: {src_ip} to {dst_ip} (port {port}, {attack_type}) - Source: {source}")
            # Lưu quy tắc
            ssh.exec_command("sudo iptables-save > /etc/iptables/rules.v4")
    else:
        print(f"[{timestamp}] IP {src_ip} to {dst_ip} already blocked - Source: {source}")

# Danh sách IP whitelist
whitelist = ["192.168.0.1", "192.168.0.2", "192.168.111.1", "192.168.111.2","224.0.0.251","158.247.7.204", "8.8.8.8"]

while True:
    try:
        print(f"Đang chạy tại {time.strftime('%H:%M:%S', time.localtime())}")
        # Truy vấn tất cả log có event.kind: alert trong 1 phút qua
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-1m"}}},
                        {"term": {"event.kind": "alert"}}
                    ]
                }
            }
        }
        
        response = es.search(index=".ds-filebeat-*", body=query)
        print("Elasticsearch query succeeded")

        # Xử lý từng log
        for hit in response['hits']['hits']:
            source = hit['_source']
            timestamp = source.get('@timestamp')
            rule_name = source.get('rule', {}).get('name', 'Unknown Rule')

            # Kiểm tra rule.name để quyết định chặn hay chỉ alert
            if rule_name in ALERT_ONLY_RULES:
                print(f"[{timestamp}] Alert only: {rule_name}")
                continue

            # Xử lý log IDS
            if 'flow_summary' in source and 'source' in source:
                src_ips = source['source'].get('ip_list', [])
                dst_ip = source['destination'].get('ip')
                dst_ports = source['destination'].get('port_list', [])
                proto = source['network'].get('transport')
                attack_type = rule_name  # Ví dụ: "DDoS ATTACK DETECTED_TCP_PORT:22"

                for ip in src_ips:
                    # Kiểm tra whitelist và 192.168.111.141 làm nguồn
                    if ip not in whitelist and ip != "192.168.111.141" and dst_ip not in whitelist:
                        # Chặn cho mọi port trong destination.port_list
                        for port in dst_ports:
                            block_ip(ip, dst_ip, attack_type, port, proto, source="IDS")
                    else:
                        print(f"[{timestamp}] Skipped blocking {ip} to {dst_ip} (in whitelist or 192.168.111.141 as source) - Source: IDS")

            # Xử lý log Suricata
            elif 'suricata' in source and 'source' in source:
                src_ip = source['source'].get('ip')
                dst_ip = source['destination'].get('ip')
                dst_port = source['destination'].get('port')
                proto = source['network'].get('transport')
                attack_type = rule_name  # Sử dụng rule.name thay vì signature

                if src_ip and dst_ip and src_ip not in whitelist:
                    if src_ip != "192.168.111.141":
                        block_ip(src_ip, dst_ip, attack_type, dst_port, proto, source="Suricata")
                    else:
                        print(f"[{timestamp}] Skipped blocking {src_ip} to {dst_ip} (in whitelist or 192.168.111.141 as source) - Source: Suricata")

            # Xử lý log Zeek
            elif 'zeek' in source:
                # Hiện tại log Zeek không có src_ip và dst_ip rõ ràng, cần bổ sung nếu có
                src_ip = source.get('source').get('ip') 
                dst_ip = source['destination'].get('ip')
                dst_port = source['destination'].get('port')
                proto = source['network'].get('transport')
                attack_type = rule_name

                if src_ip and dst_ip and src_ip not in whitelist:
                    if src_ip != "192.168.111.141":
                        block_ip(src_ip, dst_ip, attack_type, dst_port, proto, source="Zeek")
                    else:
                        print(f"[{timestamp}] Skipped blocking {src_ip} to {dst_ip} (in whitelist or 192.168.111.141 as source) - Source: Zeek")

    except Exception as e:
        print(f"Error: {e}")
    time.sleep(30)
