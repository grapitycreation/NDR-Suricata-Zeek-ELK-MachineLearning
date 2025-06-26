from flask import Flask, request, jsonify
import os
import tempfile
import mimetypes
from datetime import datetime

app = Flask(__name__)

# Đường dẫn lưu file tạm
TEMP_DIR = tempfile.gettempdir()

@app.route('/post', methods=['POST'])
def handle_post():
    # Lấy thông tin yêu cầu
    client_ip = request.remote_addr
    headers = dict(request.headers)
    response = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'client_ip': client_ip,
        'method': request.method,
        'url': request.url,
        'headers': headers,
        'form_data': {},
        'files': {},
        'raw_data': None
    }

    # Xử lý form-data
    if request.form:
        response['form_data'] = dict(request.form)

    # Xử lý file được gửi
    if request.files:
        for file_key, file in request.files.items():
            if file.filename:
                # Lưu file tạm
                temp_path = os.path.join(TEMP_DIR, file.filename)
                file.save(temp_path)
                
                # Lấy thông tin file
                file_size = os.path.getsize(temp_path)
                mime_type, _ = mimetypes.guess_type(temp_path)
                
                # Đọc nội dung file nếu là text
                content = None
                if mime_type and mime_type.startswith('text'):
                    with open(temp_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()[:1024]  # Giới hạn 1KB để tránh file lớn
                
                response['files'][file_key] = {
                    'filename': file.filename,
                    'size_bytes': file_size,
                    'mime_type': mime_type or 'unknown',
                    'content_preview': content
                }
                
                # Xóa file tạm
                os.remove(temp_path)

    # Xử lý raw data (nếu không có file hoặc form)
    if not request.files and not request.form and request.data:
        response['raw_data'] = request.data.decode('utf-8', errors='ignore')[:1024]  # Giới hạn 1KB

    return jsonify(response), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)