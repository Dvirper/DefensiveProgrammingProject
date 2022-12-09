import socket
import selectors
from protocol import handle_server_tcp_request

DEFAULT_PORT = 1234

sel = selectors.DefaultSelector()
def accept(sock):
    conn, addr = sock.accept()  # Should be ready
    print('accepted', conn, 'from', addr)
    conn.setblocking(False)
    conn.settimeout(None)
    sel.register(conn, selectors.EVENT_READ, handle_server_tcp_request)

def server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', port))
        s.listen(100)
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ, accept)
        print('Server is running')
        while True:
            events = sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj)

if __name__ == '__main__':
    try:
        with open('port.info') as f:
            port = int(f.read())
            server(port)
    except FileNotFoundError:
        print("porf.info doesn't exist, Work with default port - 1234")
        server(DEFAULT_PORT)

