import os
import socket
import signal
from contextlib import contextmanager

@contextmanager
def child_process(fn, *args, **kws):
    """ Create a child process and run fn.

        After context completes, the child
        process is sent a SIGTERM.
    """
    child_pid = os.fork()
    if child_pid: # parent process yields
       try:
           yield
       finally:
           os.kill(child_pid, signal.SIGTERM)
    else: # child process
       fn( *args, **kws)

@contextmanager
def child_server(server, *args, **kws):
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

    def serve():
        c.close()
        server(s, *args, **kws)
        assert False, "Server returned!"

    with child_process(serve):
       s.close()
       yield c
