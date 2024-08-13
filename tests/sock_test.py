from certified.test import child_server

def echo(sock):
    while True:
        msg = sock.recv(1024)
        sock.sendall(msg)

def test_cxn():
    with child_server(echo) as sock:
        sock.sendall(b"Hello")
        print( sock.recv(128) )
