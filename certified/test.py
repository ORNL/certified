import os
import socket
import signal
from contextlib import contextmanager

@contextmanager
def child_server(server):
    """ Create a UNIX socket and run the server
        in a child process.

        After context completes, the server is
        sent a SIGTERM.

        >>> def echo(sock):
        >>>     while True:
        >>>         msg = sock.recv(1024)
        >>>         sock.sendall(msg)
        >>> def run():
        >>>     with child_server(echo) as sock:
        >>>         sock.sendall(b"Hello")
        >>>         print( sock.recv(1024) )
    """
    c, s = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    child_pid = os.fork()
    if child_pid: # parent process = client
       s.close()
       try:
           yield c
       finally:
           #print("Client done.")
           os.kill(child_pid, signal.SIGTERM)
    else: # child process = server
       c.close()
       server(s)
       assert False, "Server returned!"


