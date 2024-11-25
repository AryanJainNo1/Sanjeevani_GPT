import socket

bind = "0.0.0.0:80"
workers = 4
worker_class = "eventlet"
timeout = 120
keepalive = 5
preload_app = True
forwarded_allow_ips = '*'

# Force IPv4
bind_socket_options = [
    (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
    (socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
] 