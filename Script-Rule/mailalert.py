from elasticsearch import Elasticsearch
import time
import smtplib
from email.mime.text import MIMEText

# Kết nối Elasticsearch
es = Elasticsearch(['http://10.81.89.131:9200'])  # Cập nhật URL từ log mới

# Cấu hình email
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "accthvip@gmail.com"  # Thay bằng email của bạn
SENDER_PASSWORD = "njae ekfq bxti zmkz"  # Thay bằng App Password nếu dùng 2FA
RECEIVER_EMAIL = "accvipth86@gmail.com"  # Thay bằng email người quản trị

def send_email(subject, body):
    """Gửi email với chủ đề và nội dung."""
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")

while True:
    try:
        print(f"Đang giám sát alert tại {time.strftime('%H:%M:%S', time.localtime())}")
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
        print(f"Elasticsearch query succeeded, found {len(response['hits']['hits'])} alerts")

        # Xử lý từng log alert
        for hit in response['hits']['hits']:
            source = hit['_source']
            timestamp = source.get('@timestamp', 'Unknown')
            rule_name = source.get('rule', {}).get('name', 'Unknown Rule')

            # Trích xuất thông tin
            module = source.get('event', {}).get('module', 'Unknown')
            kind = source.get('event', {}).get('kind', 'Unknown')
            msg = rule_name  # Sử dụng rule.name làm msg
            src_ip = source.get('source', {}).get('ip') or source.get('source', {}).get('ip_list', ['Unknown'])[0] if source.get('source') else 'Unknown'
            src_port = source.get('source', {}).get('port') or source.get('source', {}).get('port_list', ['Unknown'])[0] if source.get('source') else 'Unknown'
            dst_ip = source.get('destination', {}).get('ip', 'Unknown')
            dst_port = source.get('destination', {}).get('port') or source.get('destination', {}).get('port_list', ['Unknown'])[0] if source.get('destination') else 'Unknown'

            # Tạo nội dung email
            email_body = f"""
            Alert Details:
            - Timestamp: {timestamp}
            - Module: {module}
            - Kind: {kind}
            - Message: {msg}
            - Source IP: {src_ip}
            - Source Port: {src_port}
            - Destination IP: {dst_ip}
            - Destination Port: {dst_port}
            """
            subject = f"New Alert Detected at {timestamp}"

            # Gửi email
            send_email(subject, email_body)
            print(f"Sent email for alert at {timestamp}")

    except Exception as e:
        print(f"Error: {e}")
    time.sleep(30)  # Kiểm tra mỗi 30 giây
