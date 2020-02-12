#!/usr/bin/env python3

import concurrent.futures
from client import client_runner
from proxy import proxy_handler
import pprint
import pathlib

class Test:

    def __init__(self, name, proxy_sock, conn_handlers,):
        self.name = name
        self.proxy_sock = proxy_sock
        self.conn_handlers = conn_handlers

    def run(self):
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(self.conn_handlers)+1)
        futures = {}
        # clients
        for handler in self.conn_handlers:
            futures[executor.submit(client_runner, handler[0], handler[1], handler[2],)] = handler[0].__name__
        # proxy
        futures[executor.submit(proxy_handler, self.proxy_sock)] = 'proxy'
        # wait for all futures finish the execution - BLOCKING
        done, not_done = concurrent.futures.wait(futures)
        executor.shutdown()
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
                pathlib.Path('logs/').mkdir(exist_ok=True)
                cfile = open('logs/{}.client{}.{}.log'.format(self.name, client_id, futures[d]), 'w')
                mesg_id = 0
                for mesg in d.result():
                    pprint.pprint(mesg_id, cfile)
                    pprint.pprint(mesg, cfile)
                    mesg_id += 1
                cfile.close()
        pathlib.Path('logs/').mkdir(exist_ok=True)
        pfile = open('logs/{}.proxy.log'.format(self.name), 'w')
        mesg_id = 0
        for mesg in proxy:
            pprint.pprint(mesg_id, pfile)
            pprint.pprint(mesg, pfile)
            mesg_id += 1
        pfile.close()
        # check sent messages against reports from proxy
        for client in clients:
            line = 0
            for mesg in client:
                proxy.remove(mesg)
                line += 1
        if proxy:
            raise Exception('reported messages does not match')
        print(self.name, ' passed')
