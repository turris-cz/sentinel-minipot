import socket


def client_runner(handler, host, port):
    """ Runs given handler on given host and port and returns list of handler
    generated proxy reports as a list of dictionaries.

    Parameters:
        handler: callable
            It must return list of generated proxy reports
        host: string
        port: int """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        data = handler(s)
    return data
