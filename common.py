#!/bin/python

import socket
import struct
import sys
import logging
import time
import getopt
import json

LOG_HEAVY = 3
LOG_STATS = 6
LOG_VERBOSE = 15

class AliveObject(object):
    def __init__(self, pool, snooze_limit):
        '''
        Params
        ------
        pool: set

        snooze_limit: integer
            the max time (in seconds) that the object is not poked before regards it as dead
        '''
        self._alive_pool = pool
        self._snooze_limit = snooze_limit
        self._last_active = time.time()

        self._alive_pool.add(self)

    def dead(self):
        self._alive_pool.discard(self)

    def poke(self):
        self._last_active = time.time()

    def check_alive(self):
        if time.time() - self._last_active > self._snooze_limit:
            self.dead()

class MACHeader:
    def __init__(self, data):
        self.dst = data[0:6]
        self.src = data[6:12]
        self.etype = data[12:14]

class IPHeader:
    def __init__(self, data):
        iph = struct.unpack("!BBHHHBBH4s4s", data)
        self.verihl, self.tos, self.tol, \
        self.id, self.flag, \
        self.ttl, self.proto, self.chk, \
        self.src, self.dst = iph

        self.ver = self.verihl >> 4
        self.ihl = self.verihl & 15

        self.source = socket.inet_ntop(socket.AF_INET, self.src)
        self.destination = socket.inet_ntop(socket.AF_INET, self.dst)

class TCPHeader:
    TCP_SYN = 2
    TCP_ACK = 16

    def __init__(self, data):
        tcph = struct.unpack("!HHIIBBHHH", data)
        self.sport, self.dport, \
        self.seq, self.ack, \
        self.off, self.flag, self.wnd, \
        self.chk, self.urge = tcph

class UDPHeader:
    def __init__(self, data):
        udph = struct.unpack("!HHHH", data)
        self.sport, self.dport, \
        self.len, self.chk = udph

def loadOptions(shortopts, longopts):
    try:
        opts, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
    except getopt.GetoptError as err:
        logging.error(err)
        logging.critical('Failed to load options.')
        return None, None
    return opts, args

def loadConfig(filename, default_config):
    try:
        with open(filename) as f:
            config = json.load(f)
    except Exception as err:
        logging.error(err)
        logging.critical('Failed to load config.')
        return None
    return {**default_config, **config}

def setupLogging(logger, format):
    logging.addLevelName(LOG_HEAVY, 'HEAVY')
    logging.addLevelName(LOG_STATS, 'STATS')
    logging.addLevelName(LOG_VERBOSE, 'VERBOSE')
    
    herr = logging.StreamHandler(sys.stderr)
    herr.setLevel(logging.ERROR)
    herr.setFormatter(logging.Formatter(format))
    logger.addHandler(herr)

    hout = logging.StreamHandler(sys.stdout)
    hout.addFilter(lambda record: record.levelno < logging.ERROR)
    hout.setFormatter(logging.Formatter(format))
    logger.addHandler(hout)
