@load base/frameworks/notice
@load base/protocols/dns
@load base/utils/site

module DNSTunnelingDetect;

export {
    redef enum Notice::Type += {
        SuspiciousDomainDetected,
        HighRateDnsQuery,
        LongDnsNameQuery,
        DotInDnsQuery,
        AReply,
        CNAMEReply
    };

    # Dải mạng nội bộ
    const internal_networks: set[subnet] = {
        192.168.1.0/24,
        192.168.2.0/24,
        192.168.3.0/24,
        8.8.8.8/32
    } &redef;

    const dns_threshold = 15;  # Số DNS request cho phép trong khoảng thời gian
    const dns_threshold_a_reply=5;
    const dns_threshold_cname_reply=5;
    const window_seconds = 30secs;

    # Danh sách domain đáng ngờ (blacklist)
    const suspicious_domains: set[string] = {
        "example-malicious.com",
        "tunnel.badactor.org"
    } &redef;

    # Danh sách domain an toàn (whitelist, tùy chỉnh)
    const trusted_domains: set[string] = {
        "google.com",
        "cloudflare.com",
        "dns.google"
    } &redef;
}

# Table đếm DNS request theo IP
global dns_counter: table[addr] of count &default=0;
global dns_counter_a_reply: table[addr] of count &default=0;
global dns_counter_cname_reply: table[addr] of count &default=0;

global dns_last_time: table[addr] of time &default=network_time();
global dns_last_time_a_reply: table[addr] of time &default=network_time();
global dns_last_time_cname_reply: table[addr] of time &default=network_time();


function extract_domain(query: string): string
{
    local parts = split_string(query, /\./);
    if (|parts| >= 2)
        return cat(parts[|parts|-2], ".", parts[|parts|-1]);
    return query;
}

#==== event ====
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) 
{
    local client = c$id$orig_h;
    local domain= extract_domain(query);
    if (domain in trusted_domains) return;
    if (domain in suspicious_domains)
        {
            NOTICE([$note=SuspiciousDomainDetected,
            $msg=fmt("ALERT: Suspicious Domain %s Detected from IP %s",domain, client),
            $conn=c,
            $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
            ]);
            return;
        }

    if (client in internal_networks){

    # Kiểm tra nếu đã quá window_seconds kể từ lần đầu tiên
    if (network_time() - dns_last_time[client] > window_seconds)
    {
        # Reset counter và thời gian
        dns_counter[client] = 1;
        dns_last_time[client] = network_time();
    }
    else
    {
        dns_counter[client] += 1;
        if (dns_counter[client] > dns_threshold)
        {
            NOTICE([$note=HighRateDnsQuery,
            $msg=fmt("ALERT: High DNS request Rate to domain %s from %s", domain, client),
            $conn=c,
            $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
            ]);
            
            # Có thể reset luôn để tránh lặp lại liên tục
            dns_counter[client] = 0;
            dns_last_time[client] = network_time();
        }
    }

        # Giới hạn độ dài query name
    if ( |query| > 50 )
        {
            NOTICE([$note=LongDnsNameQuery,
            $msg=fmt("ALERT: DNS requets name too long: %s chars - Domain: %s", |query| , domain),
            $conn=c,
            $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
            ]);
        }
    # Đếm số dấu chấm - độ sâu subdomain
    local dot_count = |split_string(query, /\./)|;
    if ( dot_count >= 5 )
        {
             NOTICE([$note=DotInDnsQuery,
            $msg=fmt("ALERT: Subdomain detected %s. Number of dot: %s", query, dot_count),
            $conn=c,
            $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
            ]);
        }
}
}

# event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
# {
#     local server = c$id$orig_h;
#     local client = c$id$resp_h;
#     local query = ans$query;
#     local domain= extract_domain(query);
#     if (domain in trusted_domains) return;
#     if (domain in suspicious_domains)
#         {
#             NOTICE([$note=AReply,
#             $msg=fmt("ALERT: Suspicious DNS A Reply Domain %s Detected to IP %s", domain, client),
#             $conn=c,
#             $identifier=fmt("%s:%s->%s:%s", server, c$id$orig_p, client, c$id$resp_p),
#             ]);
#             return;
#         }

#     if (client in internal_networks)
#     {
#     # Kiểm tra nếu đã quá window_seconds kể từ lần đầu tiên
#         if (network_time() - dns_last_time_a_reply[client] > window_seconds)
#         {
#             # Reset counter và thời gian
#             dns_counter_a_reply[client] = 1;
#             dns_last_time_a_reply[client] = network_time();
#         }
#         else
#         {
#             dns_counter_a_reply[client] += 1;
#             if (dns_counter_a_reply[client] > dns_threshold_a_reply)
#             {
#                 NOTICE([$note=AReply,
#                 $msg=fmt("ALERT: High DNS A Reply Rate from domain %s to %s.", domain, c$id$resp_h),
#                 $conn=c,
#                 $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
#                 ]);
                
#                 # Có thể reset luôn để tránh lặp lại liên tục
#                 dns_counter_a_reply[client] = 0;
#                 dns_last_time_a_reply[client] = network_time();
#             }
#         }

#         # Giới hạn độ dài query name
#     if ( |query| > 50 )
#         {
#             NOTICE([$note=AReply,
#             $msg=fmt("ALERT: DNS A Reply name too long: %s chars - Domain: %s.", |query| , domain),
#             $conn=c,
#             $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
#             ]);
#         }
#     # Đếm số dấu chấm - độ sâu subdomain
#     local dot_count = |split_string(query, /\./)|;
#     if ( dot_count >= 5 )
#         {
#              NOTICE([$note=AReply,
#             $msg=fmt("ALERT: DNS A Reply Subdomain detected %s. Number of dot: %s.", query, dot_count),
#             $conn=c,
#             $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
#             ]);
#         }
#     }
# }

# event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
# {
#     local server = c$id$orig_h;
#     local client = c$id$resp_h;
#     local query = ans$query;
#     local domain= extract_domain(query);
#     if (domain in trusted_domains) return;
#     if (domain in suspicious_domains)
#         {
#             NOTICE([$note=CNAMEReply,
#             $msg=fmt("ALERT: Suspicious CNAME Reply Domain %s Detected from IP %s to IP %s",domain, server,client),
#             $conn=c,
#             $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
#             ]);
#             return;
#         }

#     if (client in internal_networks){

#     # Kiểm tra nếu đã quá window_seconds kể từ lần đầu tiên
#     if (network_time() - dns_last_time_cname_reply[client] > window_seconds)
#     {
#         # Reset counter và thời gian
#         dns_counter_cname_reply[client] = 1;
#         dns_last_time_cname_reply[client] = network_time();
#     }
#     else
#     {
#         dns_counter_cname_reply[client] += 1;
#         if (dns_counter_cname_reply[client] > dns_threshold_cname_reply)
#         {
#             NOTICE([$note=CNAMEReply,
#             $msg=fmt("ALERT: High DNS CNAME Reply rate from domain %s to %s", domain, client),
#             $conn=c,
#             $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
#             ]);
            
#             # Có thể reset luôn để tránh lặp lại liên tục
#             dns_counter_cname_reply[client] = 0;
#             dns_last_time_cname_reply[client] = network_time();
#         }
#     }

#     if ( |query| > 50 )
#         {
#             NOTICE([$note=CNAMEReply,
#             $msg=fmt("ALERT: DNS CNAME Reply name too long: %s chars - Domain: %s", |query| , domain),
#             $conn=c,
#             $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
#             ]);
#         }
#     # Đếm số dấu chấm - độ sâu subdomain
#     local dot_count = |split_string(query, /\./)|;
#     if ( dot_count >= 5 )
#         {
#              NOTICE([$note=CNAMEReply,
#             $msg=fmt("ALERT: CNAME Reply subdomain detected %s. Number of dot: %s", query, dot_count),
#             $conn=c,
#             $identifier=fmt("%s:%s->%s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
#             ]);
#         }
# }
# }