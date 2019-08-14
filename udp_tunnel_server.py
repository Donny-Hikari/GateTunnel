#!/bin/python

import socket
import struct
import signal
import logging
import random

from eventloop import EventHandler, EventLoop, AsyncHandler, AsyncUDPHandler
from common import AliveObject, LOG_HEAVY, LOG_STATS, LOG_VERBOSE, loadConfig, loadOptions, setupLogging

ConfigFile = './config/gateway-server.json'
LogLevel = logging.INFO

DefaultConfig = {
    'tunnel_host': "0.0.0.0",
    'tunnel_port': 32824,
    'max_client': 200,
    'max_agents': 1000,
    'select_time_out': 600 / 1000,
    'alive_time_limit': {
        'tunnel': 900,
        'udp_agent': 20,
    }, # seconds
}

class UDPAgent(AsyncUDPHandler, AliveObject):
    def __init__(self, loop, server, agents_table, dispatch_table, host, alive_conf):
        AliveObject.__init__(self, alive_conf['pool'], alive_conf['snooze_limit']['udp_agent'])

        self._loop = loop
        self._server = server
        self._agents_table = agents_table
        self._dispatch_table = dispatch_table
        self._host = host

        if self._host not in self._dispatch_table:
            self._dispatch_table[self._host] = {}
        host_info = self._dispatch_table[self._host]
        host_info['agent'] = self
        
        self._conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._conn.setblocking(False)
        self._id = self._conn.fileno()
        self._agents_table.append(self)

        logging.log(LOG_VERBOSE, 'UDPAgent %d Agent setup', self._id)

        AsyncUDPHandler.__init__(self, self._loop, self._conn)

    def dead(self):
        self.close()

    def close(self):
        AliveObject.dead(self)

        self._loop.unregister(self._conn, EventLoop.ALL_EVENT)

        self._agents_table.remove(self)
        if self._dispatch_table[self._host]['agent'] == self:
            del self._dispatch_table[self._host]

        try:
            self._conn.close()
        except Exception as err:
            logging.debug(err)

        logging.log(LOG_VERBOSE, 'UDPAgent %d Agent shutdown', self._id)

    def sendto(self, data, addr):
        AliveObject.poke(self)

        logging.debug("UDPAgent %d Sending data %s:%d -> %s:%d length %d", self._id, self._host[0], self._host[1], addr[0], addr[1], len(data))
        self.async_write(data, addr)

    def handle_error(self, err):
        self.close()

    def handle_read(self, data, addr):
        AliveObject.poke(self)

        logging.debug("UDPAgent %d Forwarding data %s:%d -> %s:%d length %d", self._id, addr[0], addr[1], self._host[0], self._host[1], len(data))
        self._server.forward(addr, data, self._host)

class ClientTCPConn(AsyncHandler, AliveObject):
    def __init__(self, loop, conn, addr, max_agents, alive_conf):
        self._alive_conf = alive_conf
        AliveObject.__init__(self, self._alive_conf['pool'], self._alive_conf['snooze_limit']['tunnel'])
        
        self._loop = loop
        self._conn = conn
        self._addr = addr
        self._id = self._conn.fileno()
        self._data_buffer = b''
        
        self._max_agents = max_agents
        self._agents = []
        self._dispatch_table = {}

        logging.log(LOG_VERBOSE, 'Tunnel %d Connection from %s', self._id, addr)
        
        super().__init__(self._loop, self._conn)

    def dead(self):
        self.close()

    def close(self):
        AliveObject.dead(self)

        self._loop.unregister(self._conn, EventLoop.ALL_EVENT)

        try:
            self._conn.close()
        except Exception as err:
            logging.debug(err)

        for agent in list(self._agents):
            try:
                agent.close()
            except Exception as err:
                logging.debug(err)

        logging.log(LOG_VERBOSE, 'Tunnel %d Connection closed for %s', self._id, self._addr)

    def forward(self, src, data, dst):
        AliveObject.poke(self)
        
        src_ip = socket.inet_pton(socket.AF_INET, src[0])
        dst_ip = socket.inet_pton(socket.AF_INET, dst[0])
        header = struct.pack("!4sH4sHH", src_ip, src[1], dst_ip, dst[1], len(data))
        self.async_write(header + data)

    def handle_error(self, err):
        self.close()

    def handle_read(self, data):
        AliveObject.poke(self)

        header_len = 14
        
        self._data_buffer = self._data_buffer + data
        data = self._data_buffer
        if len(data) < header_len:
            return
        src_ip, src_port, dst_ip, dst_port, l = struct.unpack("!4sH4sHH", data[0:header_len])
        if len(data) < header_len+l:
            return
        src_ip = socket.inet_ntop(socket.AF_INET, src_ip)
        dst_ip = socket.inet_ntop(socket.AF_INET, dst_ip)
        
        src = (src_ip, src_port)
        if src not in self._dispatch_table:
            UDPAgent(self._loop, self, self._agents, self._dispatch_table, src, self._alive_conf)
        agent = self._dispatch_table[src]['agent']
        agent.sendto(data[header_len:], (dst_ip, dst_port))

        self._data_buffer = data[header_len+l:]
        self.handle_read(b'')

class UDPTunnelServer(EventHandler):
    def __init__(self, loop, host, port, max_client, max_agents, alive_conf):
        self._alive_conf = alive_conf

        self._loop = loop
        self._host = host
        self._port = port
        self._max_client = max_client
        self._max_agents = max_agents

        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._server.bind((self._host, self._port))
        except:
            logging.critical('Failed to bind port %d on %s', self._port, self._host)
            exit(1)
        self._server.listen(self._max_client)
        self._server.setblocking(False)
        logging.info('Listening on %s:%d', self._host, self._port)

        self._loop.register(self._server, self, EventLoop.READ_EVENT)

    def close(self):
        logging.debug('Server shutting down.')
        self._loop.unregister(self._server, EventLoop.ALL_EVENT)

        try:
            self._server.close()
        except Exception as err:
            logging.error(err)

        logging.info('Server shutdown.')

    def onRead(self, e):
        conn, addr = self._server.accept()
        conn.setblocking(False)
        ClientTCPConn(self._loop, conn, addr, self._max_agents, self._alive_conf)

def main():
    global LogLevel, ConfigFile, DefaultConfig
    setupLogging(logging.getLogger(), format='[%(levelname)-s %(asctime)s]: %(message)s')
    logging.getLogger().setLevel(level=LogLevel)

    # load arguments
    opts, args = loadOptions("c:vl:", [ 'configuration=', 'verbose', 'log-level=' ])
    for opt, arg in opts:
        if opt in [ '-c', '--configuration' ]:
            ConfigFile = str(arg)
        elif opt in [ '-v', '--verbose' ]:
            LogLevel = LOG_VERBOSE
        elif opt in [ '-l', '--log-level' ]:
            LogLevel = arg

    try:
        LogLevel = int(LogLevel)
    except ValueError:
        logging.critical('log-level must be an integer, but received %s', str(LogLevel))
        return
    
    # Reflect log-level change
    logging.getLogger().setLevel(level=LogLevel)

    # load configuration
    config = loadConfig(ConfigFile, DefaultConfig)
    if config == None:
        return


    loop = EventLoop()
    alive_pool = set()

    server = UDPTunnelServer(loop, config['tunnel_host'], config['tunnel_port'],
        max_client=config['max_client'], max_agents=config['max_agents'],
        alive_conf={ 'pool': alive_pool, 'snooze_limit': config['alive_time_limit'] })

    def int_handler(signum, _):
        logging.debug('Received SIGINT.')
        exit(1)
    signal.signal(signal.SIGINT, int_handler)

    global Stopping
    Stopping = False

    def exithandler(signum, _):
        logging.debug('Received SIGQUIT.')
        global Stopping
        Stopping = True
    signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), exithandler)

    while not Stopping:
        loop.loop(config['select_time_out'])

        for obj in set(alive_pool):
            obj.check_alive()


    # cleanup
    for event_type in [ EventLoop.READ_EVENT, EventLoop.WRITE_EVENT, EventLoop.EXCEPT_EVENT ]:
        _list = loop.get_list(event_type)
        for sock in _list:
            print(sock)
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except Exception as err:
                logging.debug(err)

    server.close()

if __name__ == "__main__":
    main()
