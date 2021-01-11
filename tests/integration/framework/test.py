import concurrent.futures
import pprint
import pathlib


from framework.client import client_runner


OUT_CAPT = "out_capt"


class Test:
    """ Provides companions to Minipots from both sides and interface for convinient testing.

    Attributes:
        name: str
            name of the test
        path_to_log: string
            path to directory where logs will be saved
        out_capt_handler: tuple (handler, *args)
            handler: callable
                Function implementing collection of minipot pipeline output
                It must return list of captured Sentinel messages.
            *args: parameters passed to handler
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

    def __init__(self, name, path_to_log, out_capt_handler, conn_handlers):
        """ Assigns parameters to dedicated instance attributes.

        Parameters:
            name: str
                name of the test
            path_to_log: string
                path to directory where logs will be saved
            out_capt_handler: tuple (handler, *args)
                handler: callable
                    Function implementing collection of minipot pipeline output
                    It must return list of captured Sentinel messages.
                *args: parameters passed to handler
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
        self.path_to_log = path_to_log
        self.out_capt_handler = out_capt_handler
        self.conn_handlers = conn_handlers

    def run(self):
        """ Runs handlers given in constructor each in separate thread and matches
        generated reports from handlers with reports received from ZMQ socket.
        If matching of generated and received reports fails or if handler
        returns exception the test failed. If test passed the message is printed to stdout. """
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(self.conn_handlers) + 1)
        futures = {}
        # clients
        for handler in self.conn_handlers:
            futures[executor.submit(client_runner, *handler,)] = handler[0].__name__
        # minipot pipeline output capture
        futures[executor.submit(*self.out_capt_handler)] = OUT_CAPT
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
            elif futures[d] == OUT_CAPT:
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
        with open(root_path / 'pipeline_out.log', "w") as pfile:
            mesg_id = 0
            for mesg in proxy:
                pprint.pprint(mesg_id, pfile)
                pprint.pprint(mesg, pfile)
                mesg_id += 1
        # check sent messages against reports from proxy
        for client in clients:
            for mesg in client:
                if mesg in proxy:
                    proxy.remove(mesg)
                else:
                    raise Exception('reported messages does not match')
        print(self.name, ' passed')


class HandlerRunner:
    """ Provides interface for running minipot client handlers each in separate thread.

    Attributes:
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
            Runs handlers given in contructor each in separate thread. """

    def __init__(self, handlers):
        """ Assigns parameters to dedicated instance attributes.

        Parameters:
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
        self.handlers = handlers

    def run(self):
        """ Runs handlers given in constructor each in separate thread and matches
        generated reports from handlers with reports received from ZMQ socket.
        If matching of generated and received reports fails or if handler
        returns exception the test failed. If test passed the message is printed to stdout. """
        executor = concurrent.futures.ThreadPoolExecutor()
        futures = []
        for handler in self.handlers:
            futures.append(executor.submit(client_runner, handler[0], handler[1], handler[2]))
        print("All futures submited.")
        # wait for all futures finish the execution - BLOCKING
        concurrent.futures.wait(futures)
        print("All futures done.")
        executor.shutdown()
