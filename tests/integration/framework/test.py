import concurrent.futures
import pprint
import pathlib


from framework.client import client_runner
from framework.proxy import proxy_handler


class Test:
    """ Provides companions to Minipots from both sides and interface for convinient testing.

    Attributes:
        name: str
            name of the test
        path_to_log: string
            path to directory where logs will be saved
        proxy_sock: string
            address string of ZMQ socket in form "protocol://interface:port"
        conn_handlers: list of tuples (handler, host, port)
            handler: callable
                Function implementing test case. It must have socket object as a parameter.
                It returns list of generated proxy reports - dictionaries for later check
                or an exception if communication with Minipots went wrong.
            host: string
                Minipots host identification
            port: int
                Minipots port identification
            Host and port are used to create socket object socket used as input
            parameter to handler function.

    Methods:
        run:
            Runs handlers given in contructor each in separate thread and matches
            generated reports from handlers with reports received from ZMQ socket. """

    def __init__(self, name, path_to_log, proxy_sock, conn_handlers):
        """ Assigns parameters to dedicated instance attributes.

        Parameters:
            name: str
                name of the test
            path_to_log: string
                path to directory where logs will be saved
            proxy_sock: string
                address string of ZMQ socket in form "protocol://interface:port"
            conn_handlers: list of tuples (handler, host, port)
            handler: callable
                Function implementing test case. It must have socket object as a parameter.
                It returns list of generated proxy reports - dictionaries for later check
                or an exception if communication with Minipots went wrong.
            host: string
                Minipots host identification
            port: int
                Minipots port identification

            Host and port are used to create socket object socket used as input
            parameter to handler function.
        """
        self.name = name
        self.proxy_sock = proxy_sock
        self.conn_handlers = conn_handlers
        self.path_to_log = path_to_log

    def run(self):
        """ Runs handlers given in constructor each in separate thread and matches
        generated reports from handlers with reports received from ZMQ socket.
        If matching of generated and received reports fails or if handler
        returns exception the test failed. If test passed the message is printed to stdout. """
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(self.conn_handlers) + 1)
        futures = {}
        # clients
        for handler in self.conn_handlers:
            futures[executor.submit(client_runner, handler[0], handler[1],
                                    handler[2],)] = handler[0].__name__
        # proxy
        futures[executor.submit(proxy_handler, self.proxy_sock)] = 'proxy'
        # wait for all futures finish the execution - BLOCKING
        done = concurrent.futures.wait(futures)[0]
        executor.shutdown()
        # create root directory for logs
        root_path = pathlib.Path(self.path_to_log, self.name)
        root_path.mkdir(parents=True, exist_ok=True)
        # retreive results from futures
        clients = []
        client_id = 0
        for d in done:
            # check for an exception
            if isinstance(d.result(), Exception):
                raise d.result()
            elif futures[d] == 'proxy':
                proxy = d.result()
            else:
                clients.append(d.result())
                # write client output to a log file
                with open(root_path / f"client_{client_id}_handler_{futures[d]}.log", 'w') as cfile:
                    mesg_id = 0
                    for mesg in d.result():
                        pprint.pprint(mesg_id, cfile)
                        pprint.pprint(mesg, cfile)
                        mesg_id += 1
            client_id += 1
        # write proxy output to a log file
        with open(root_path / 'proxy.log', "w") as pfile:
            mesg_id = 0
            for mesg in proxy:
                pprint.pprint(mesg_id, pfile)
                pprint.pprint(mesg, pfile)
                mesg_id += 1
        # check sent messages against reports from proxy
        for client in clients:
            line = 0
            for mesg in client:
                proxy.remove(mesg)
                line += 1
        if proxy:
            raise Exception('reported messages does not match')
        print(self.name, ' passed')
