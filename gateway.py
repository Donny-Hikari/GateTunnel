#!/bin/python

import socket
import struct
from ipaddress import ip_address, ip_network
import signal
import random

import logging
from eventloop import EventHandler, EventLoop, AsyncHandler
from common import AliveObject, \
    MACHeader, IPHeader, TCPHeader, UDPHeader, \
    LOG_STATS, LOG_VERBOSE, loadConfig, loadOptions, setupLogging

ConfigFile = './config/gateway-client.json'
LogLevel = logging.INFO # LOG_STATS

DefaultConfig = {
    'spy_target': {
        'ip': "10.0.0.192/27",
        'protocols': [socket.IPPROTO_TCP, socket.IPPROTO_UDP]
    },
    'ts_tcp_server': {
        'host': "0.0.0.0",
        'port': 32822,
        'max_client': 1000,
    },
    'ts_udp_server': {
        'host': "0.0.0.0",
        'port': 32823,
        'max_tunnel': 5,
    },
    'udp_tunnel_server': {
        'host': "127.0.0.1",
        'port': 32824,
    },
    'socks_server': {
        'host': "127.0.0.1",
        'port': 32818,
    },
    'select_time_out': 600 / 1000,
    'alive_time_limit': {
        'client_tcp': 300,
    }, # seconds
}

class SocksConn(AsyncHandler):
    STATE_ENDED = 0
    STATE_INIT = 1
    STATE_WAITING = 2
    STATE_STREAMING = 3

    def __init__(self, loop, dst_pool, pendingdst_pool, client_conn, client_host, client_port, socks_host, socks_port):
        self._loop = loop
        self._dst_pool = dst_pool
        self._pendingdst_pool = pendingdst_pool
        self._client_conn = client_conn
        self._client_host = client_host
        self._client_port = client_port
        self._socks_host = socks_host
        self._socks_port = socks_port

        self._conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._conn.setblocking(False)
        self._conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if hasattr(socket, 'TCP_FASTOPEN'):
            self._conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1)
        # no need to asynchronically resolve remote_host
        self._conn.connect_ex((self._socks_host, self._socks_port))

        self._id = self._conn.fileno()
        self._state = SocksConn.STATE_INIT
        
        super().__init__(self._loop, self._conn)

        logging.log(LOG_VERBOSE, 'SOCKS %d Open %s:%d', self._id, self._client_host, self._client_port)
        
        self.check_destination()
        if not self.has_destination():
            self._pendingdst_pool.add(self)

        self.async_write(b'\x05\x01\x00')

    def close(self):
        if self._state == SocksConn.STATE_ENDED:
            return

        self._state = SocksConn.STATE_ENDED
        self._loop.unregister(self._conn, EventLoop.ALL_EVENT)

        if not self.has_destination():
            self._pendingdst_pool.discard(self)
        
        try:
            self._client_conn.close()
        except Exception as err:
            logging.debug(err)
        
        try:
            self._conn.close()
        except Exception as err:
            logging.debug(err)

        logging.log(LOG_VERBOSE, 'SOCKS %d Close %s:%d', self._id, self._client_host, self._client_port)

    def send(self, data):
        if self._state == SocksConn.STATE_INIT or self._state == SocksConn.STATE_WAITING:
            if not hasattr(self, '_data_buffer'):
                self._data_buffer = b''
            self._data_buffer += data
        elif hasattr(self, '_data_buffer'):
            self.async_write(self._data_buffer + data)
            del self._data_buffer
        else:
            self.async_write(data)

    def has_destination(self):
        return hasattr(self, '_dst_host') and hasattr(self, '_dst_port')

    def build_socks_header(self):
        if not self.has_destination():
            raise Exception("Destination is not ready")

        b_host = socket.inet_pton(socket.AF_INET, self._dst_host)
        b_port = struct.pack('>H', self._dst_port)
        socks_header = b'\x05\x01\x00\x01' + b_host + b_port

        return socks_header

    def check_destination(self):
        if not hasattr(self, '_dst_host'): # or not hasattr(self, '_dst_port')
            addr = (self._client_host, self._client_port)
            if addr in self._dst_pool:
                addr_info = self._dst_pool[addr]
                if 'destination' in addr_info:
                    self._dst_host, self._dst_port = addr_info['destination']
                    
                    if self._state == SocksConn.STATE_WAITING:
                        self.async_write(self.build_socks_header())

                del self._dst_pool[addr]

        if self.has_destination():
            self._pendingdst_pool.discard(self)

    def handle_error(self, err):
        self.close()

    def handle_read(self, res):
        l = len(res)

        if l <= 0:
            self.close()
            return

        if self._state == SocksConn.STATE_INIT:
            if res == b'\x05\x00':
                self._state = SocksConn.STATE_WAITING
                if self.has_destination():
                    self.async_write(self.build_socks_header())
            else:
                logging.log(LOG_VERBOSE, 'SOCKS %d Server Rejected %s:%d', self._id, self._client_host, self._client_port)
                self.close()
                return

        elif self._state == SocksConn.STATE_WAITING:
            if l >= 10 and res[:4] == b'\x05\x00\x00\x01':
                self._state = SocksConn.STATE_STREAMING
                if hasattr(self, '_data_buffer'):
                    self.async_write(self._data_buffer)
                    del self._data_buffer
            else:
                logging.log(LOG_VERBOSE, 'SOCKS %d Server Unknown Data %s:%d', self._id, self._client_host, self._client_port)
                self.close()
                return
        
        elif self._state == SocksConn.STATE_STREAMING:
            try:
                self._client_conn.send(res)
            except:
                self.close()

        else:
            self.close()

class ClientTCPConn(AsyncHandler, AliveObject):
    def __init__(self, loop, dst_pool, pendingdst_pool, conn, addr, socks_host, socks_port, alive_conf):
        AliveObject.__init__(self, alive_conf['pool'], alive_conf['snooze_limit']['client_tcp'])

        logging.log(LOG_VERBOSE, 'Connection from %s', addr)

        self._loop = loop
        self._dst_pool = dst_pool
        self._pendingdst_pool = pendingdst_pool

        self._conn = conn
        self._addr = addr
        self._id = self._conn.fileno()
        self._alive = True
        
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._socks_conn = SocksConn(self._loop, self._dst_pool, self._pendingdst_pool,
            self, self._addr[0], self._addr[1],
            self._socks_host, self._socks_port)

        super().__init__(self._loop, self._conn)

    def dead(self):
        self.close()

    def close(self):
        AliveObject.dead(self)
        
        if not self._alive:
            return

        self._alive = False
        self._loop.unregister(self._conn, EventLoop.ALL_EVENT)

        try:
            self._socks_conn.close()
        except Exception as err:
            logging.debug(err)

        try:
            self._conn.close()
        except Exception as err:
            logging.debug(err)

        logging.log(LOG_VERBOSE, 'Connection closed for %s', self._addr)

    def send(self, data):
        AliveObject.poke(self)

        self.async_write(data)

    def handle_error(self, err):
        self.close()

    def handle_read(self, req):
        AliveObject.poke(self)

        if len(req) == 0:
            self.close()
            return

        try:
            self._socks_conn.send(req)
        except:
            self.close()
            return

class TSTCPServer(EventHandler):
    def __init__(self, loop, dst_pool, pendingdst_pool, host, port, socks_host, socks_port, max_client, alive_conf):
        self._loop = loop
        self._dst_pool = dst_pool
        self._pendingdst_pool = pendingdst_pool
        self._host = host
        self._port = port
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._max_client = max_client
        self._alive_conf = alive_conf

        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._server.bind((self._host, self._port))
        except:
            logging.critical('Failed to bind port %d on %s', self._port, self._host)
            exit(1)
        self._server.listen(self._max_client)
        self._server.setblocking(False)
        logging.info('Listening on %s:%d' % (self._host, self._port))

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
        ClientTCPConn(self._loop, self._dst_pool, self._pendingdst_pool,
            conn, addr,
            self._socks_host, self._socks_port,
            self._alive_conf)

class ClientUDP2TCP:
    def __init__(self, loop, dst_pool, pendingdst_pool, udp_server, virtual_addr, socks_host, socks_port):
        logging.log(LOG_VERBOSE, 'Setup tcp tunnel for udp')
        
        self._loop = loop
        self._dst_pool = dst_pool
        self._pendingdst_pool = pendingdst_pool
        self._udp_server = udp_server
        self._data_buffer = b''
        
        self._alive = True

        self._socks_host = socks_host
        self._socks_port = socks_port
        self._socks_conn = SocksConn(self._loop, self._dst_pool, self._pendingdst_pool,
            self, virtual_addr[0], virtual_addr[1],
            self._socks_host, self._socks_port)

    def close(self):
        if not self._alive:
            return

        self._alive = False

        try:
            self._socks_conn.close()
        except Exception as err:
            logging.debug(err)

        logging.log(LOG_VERBOSE, 'Shutdown tcp tunnel for udp')

    def send(self, data):
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
        self._udp_server.forward((src_ip, src_port), data[header_len:header_len+l], (dst_ip, dst_port))
        self._data_buffer = data[header_len+l:]
        self.send(b'')

    def forward(self, src, data, dst):
        src_ip = socket.inet_pton(socket.AF_INET, src[0])
        dst_ip = socket.inet_pton(socket.AF_INET, dst[0])
        header = struct.pack("!4sH4sHH", src_ip, src[1], dst_ip, dst[1], len(data))
        self._socks_conn.send(header + data)

class TSUDPServer(EventHandler):
    def __init__(self, loop, dst_pool, pendingdst_pool, host, port, tunnel_host, tunnel_port, socks_host, socks_port, max_tunnel):
        self._loop = loop
        self._dst_pool = dst_pool
        self._pendingdst_pool = pendingdst_pool
        self._host = host
        self._port = port
        self._tunnel_host = tunnel_host
        self._tunnel_port = tunnel_port
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._max_tunnel = max_tunnel
        self._tunnel_conn = [self._establish_tunnel() for t in range(self._max_tunnel)]

        self._server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._server.bind((self._host, self._port))
        except:
            logging.critical('Failed to bind port %d on %s', self._port, self._host)
            exit(1)
        self._server.setblocking(False)
        logging.info('Listening on %s:%d' % (self._host, self._port))

        self._loop.register(self._server, self, EventLoop.READ_EVENT)

    def _establish_tunnel(self):
        addr = (self._host, self._port)
        self._dst_pool[addr] = {
            'destination': (self._tunnel_host, self._tunnel_port),
        }
        return ClientUDP2TCP(self._loop, self._dst_pool, self._pendingdst_pool,
            self, (self._host, self._port),
            self._socks_host, self._socks_port)

    def close(self):
        logging.debug('Server shutting down.')
        self._loop.unregister(self._server, EventLoop.ALL_EVENT)

        try:
            self._server.close()
        except Exception as err:
            logging.error(err)

        logging.info('Server shutdown.')

    def forward(self, src, data, dst):
        self._server.sendto(data, dst)

    def onRead(self, e):
        data, addr = self._server.recvfrom(65565)
        if addr in self._dst_pool:
            dest = self._dst_pool[addr]['destination']
            tunnel_id = random.randint(0, self._max_tunnel-1)
            try:
                self._tunnel_conn[tunnel_id].forward(addr, data, dest)
            except:
                logging.log(LOG_VERBOSE, "Tunnel %d is down, restarting.", tunnel_id)
                self._tunnel_conn[tunnel_id].close()
                self._tunnel_conn[tunnel_id] = self._establish_tunnel()
        else:
            logging.log(LOG_VERBOSE, "Dropped udp package from %s:%d", addr[0], addr[1])

class SpyServer(EventHandler):
    def __init__(self, loop, dst_pool, target):
        self._loop = loop
        self._dst_pool = dst_pool
        self._target = target

        self._server = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        self._server.setblocking(False)
        logging.info('SpyServer started.')

        self._loop.register(self._server, self, EventLoop.READ_EVENT)

    def close(self):
        logging.debug('SpyServer shutting down.')
        self._loop.unregister(self._server, EventLoop.ALL_EVENT)

        self._server.close()

        logging.info('SpyServer shutdown.')

    def onRead(self, e):
        data, info = self._server.recvfrom(65565)
        interface, protocol, pkttype, hatype, mac = info
        data_p = 0
        mach = MACHeader(data[data_p:data_p+14])
        data_p += 14
        iph = IPHeader(data[data_p:data_p+20])
        data_p += iph.ihl * 4

        isTargetSent = False
        isTargetRecv = False
        if iph.proto in self._target['protocols']:
            if ip_address(iph.source) in ip_network(self._target['ip'], strict=False):
                isTargetSent = True
            elif ip_address(iph.destination) in ip_network(self._target['ip'], strict=False):
                isTargetRecv = True

        if not isTargetSent and not isTargetRecv:
            return

        if iph.proto == socket.IPPROTO_TCP:
            tcph = TCPHeader(data[data_p:data_p+20])
            porth = tcph
        elif iph.proto == socket.IPPROTO_UDP:
            udph = UDPHeader(data[data_p:data_p+8])
            porth = udph
        else:
            logging.critical("Protocol %d not supported.", iph.proto)
            exit(1)

        if isTargetSent:
            if ((iph.proto == socket.IPPROTO_TCP) and (tcph.flag & TCPHeader.TCP_SYN == TCPHeader.TCP_SYN)) \
                or (iph.proto == socket.IPPROTO_UDP):

                addr = (iph.source, porth.sport)
                self._dst_pool[addr] = {
                    'destination': (iph.destination, porth.dport)
                }
                logging.debug("Added record for %s:%d -> %s:%d proto %d", iph.source, porth.sport, iph.destination, porth.dport, iph.proto)

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
    dst_pool = {}
    pendingdst_pool = set()
    alive_pool = set()

    spy_server = SpyServer(loop, dst_pool, config['spy_target'])

    ts_tcp_server = TSTCPServer(loop, dst_pool, pendingdst_pool,
        config['ts_tcp_server']['host'], config['ts_tcp_server']['port'],
        config['socks_server']['host'], config['socks_server']['port'],
        max_client=config['ts_tcp_server']['max_client'],
        alive_conf={ 'pool': alive_pool, 'snooze_limit': config['alive_time_limit'] })

    ts_udp_server = TSUDPServer(loop, dst_pool, pendingdst_pool,
        config['ts_udp_server']['host'], config['ts_udp_server']['port'],
        config['udp_tunnel_server']['host'], config['udp_tunnel_server']['port'],
        config['socks_server']['host'], config['socks_server']['port'],
        max_tunnel=config['ts_udp_server']['max_tunnel'])

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

        for pd in set(pendingdst_pool):
            pd.check_destination()

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

    ts_tcp_server.close()
    ts_udp_server.close()
    spy_server.close()

if __name__ == '__main__':
    main()
