@load base/frameworks/notice
@load base/utils/site

module AnomalousTrafficDetect;

export {
    redef enum Notice::Type += {
        AnomalousTrafficToStrangeIP
    };

    # Dải địa chỉ mạng nội bộ (whitelist)
    const internal_networks: set[subnet] = {
        192.168.1.0/24,
        192.168.2.0/24,
        192.168.3.0/24,
	8.8.8.8/32
    } &redef;

    # Ngưỡng số lượng kết nối đến IP lạ trong thời gian ngắn
    const connection_threshold = 100;
    const time_window = 30sec;

    # Danh sách các cổng nhạy cảm (tùy chỉnh)
    const sensitive_ports: set[port] = {
        22/tcp,  # SSH
        445/tcp,  # SMB
	4444/tcp,
	1234/tcp
    } &redef;
}

function expire_connection_count(t: table[addr, addr] of count, idx: any): interval {
    return time_window;
}

# Theo dõi số lượng kết nối đến IP đích
global connection_count: table[addr, addr] of count &default=0 &expire_func=expire_connection_count;

# Hàm hết hạn cho bảng connection_count


# Hàm ghi notice
function log_anomalous_notice(c: connection, msg: string, sub: string) {
    NOTICE([$note=AnomalousTrafficToStrangeIP,
            $msg=msg,
            $sub=sub,
            $conn=c,
            $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
            $suppress_for=1hr]);
}

# Phát hiện kết nối bất thường
event connection_established(c: connection) {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local resp_port = c$id$resp_p;

    # Kiểm tra nếu IP đích không thuộc mạng nội bộ
    if ( resp !in internal_networks ) {
        # Tăng số lượng kết nối
        connection_count[orig, resp] += 1;

        # Kiểm tra ngưỡng kết nối
        if ( connection_count[orig, resp] > connection_threshold ) {
            log_anomalous_notice(c,
                fmt("Anomalous traffic detected: %d connections to strange IP %s in %s", 
                    connection_count[orig, resp], resp, time_window),
                fmt("From %s:%s to %s:%s", orig, c$id$orig_p, resp, resp_port));
        }

        # Kiểm tra nếu kết nối đến cổng nhạy cảm
        if ( resp_port in sensitive_ports ) {
            log_anomalous_notice(c,
                fmt("Connection to sensitive port %s on strange IP %s", resp_port, resp),
                fmt("From %s:%s to %s:%s", orig, c$id$orig_p, resp, resp_port));
        }
    }
}

# Phát hiện lưu lượng lớn bất thường
event connection_state_remove(c: connection) {
    local resp = c$id$resp_h;
    if ( resp !in internal_networks && c?$conn ) {
        local bytes_transferred = c$conn$orig_bytes + c$conn$resp_bytes;
        if ( bytes_transferred > 100 ) { # 10MB
            log_anomalous_notice(c,
                fmt("Large data transfer to strange IP %s: %d bytes", resp, bytes_transferred),
                fmt("From %s:%s to %s:%s", c$id$orig_h, c$id$orig_p, resp, c$id$resp_p));
        }
    }
}
