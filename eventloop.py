
import select
import signal
import socket
import errno
import logging
import traceback

from common import LOG_STATS

class EventHandler(object):
    def onRead(self, event):
        raise NotImplementedError

    def onWrite(self, event):
        raise NotImplementedError

    def onExcept(self, event):
        raise NotImplementedError

class EventLoop(object):
    READ_EVENT = 0x01
    WRITE_EVENT = 0x02
    EXCEPT_EVENT = 0x04
    ALL_EVENT = READ_EVENT | WRITE_EVENT | EXCEPT_EVENT

    def __init__(self):
        self._rlist = {}
        self._wlist = {}
        self._xlist = {}

    def _dispatch(self, sock, event_type):
        e = {
            'event_type': event_type,
            'sof': sock,
            'loop': self,
        }
        try:
            if event_type == EventLoop.READ_EVENT:
                self._rlist[sock].onRead(e)
            elif event_type == EventLoop.WRITE_EVENT:
                self._wlist[sock].onWrite(e)
            elif event_type == EventLoop.EXCEPT_EVENT:
                self._xlist[sock].onExcept(e)
        except Exception as err:
            logging.error(err)
            traceback.print_exc()

    def loop(self, timeout):
        try:
            logging.log(LOG_STATS, 'Read %d Write %d Except %d', len(self._rlist), len(self._wlist), len(self._xlist))
            rlist, wlist, xlist = select.select(self._rlist, self._wlist, self._xlist, timeout)
        except Exception as err:
            logging.error(err)
            traceback.print_exc()
            return

        for s in rlist:
            if s in self._rlist:
                self._dispatch(s, EventLoop.READ_EVENT)

        for s in wlist:
            if s in self._wlist:
                self._dispatch(s, EventLoop.WRITE_EVENT)

        for s in xlist:
            if s in self._xlist:
                self._dispatch(s, EventLoop.EXCEPT_EVENT)

    def get_list(self, event_type):
        if event_type == EventLoop.READ_EVENT:
            return self._rlist.copy()
        elif event_type == EventLoop.WRITE_EVENT:
            return self._wlist.copy()
        elif event_type == EventLoop.EXCEPT_EVENT:
            return self._xlist.copy()

    def register(self, _sock_or_file, handler, event_type):
        if _sock_or_file.fileno() == -1:
            raise Exception('Invalid sock_or_file.')
        if not isinstance(handler, EventHandler):
            raise Exception('Expected handler to be an instance of EventHandler.')
        if type(event_type) != int:
            raise Exception('Expected event_type to be int.')

        if event_type & EventLoop.READ_EVENT:
            self._rlist[_sock_or_file] = handler
        if event_type & EventLoop.WRITE_EVENT:
            self._wlist[_sock_or_file] = handler
        if event_type & EventLoop.EXCEPT_EVENT:
            self._wlist[_sock_or_file] = handler

    def unregister(self, _sock_or_file, event_type):
        if type(event_type) != int:
            raise Exception('Expected event_type to be int.')

        if event_type & EventLoop.READ_EVENT:
            if _sock_or_file in self._rlist:
                del self._rlist[_sock_or_file]
        if event_type & EventLoop.WRITE_EVENT:
            if _sock_or_file in self._wlist:
                del self._wlist[_sock_or_file]
        if event_type & EventLoop.EXCEPT_EVENT:
            if _sock_or_file in self._xlist:
                del self._xlist[_sock_or_file]


class AsyncHandler(EventHandler):
    BUFFER_SIZE = 14336

    def __init__(self, loop, sock):
        self._loop = loop
        self._sock = sock
        self._data_to_write = b''
        self._read_buffer_size = AsyncHandler.BUFFER_SIZE
        self._closing = False

        self._loop.register(self._sock, self, EventLoop.READ_EVENT)

    def close_gracefully(self):
        if len(self._data_to_write) == 0:
            self.close()
        else:
            self._closing = True
            self._sock.shutdown(socket.SHUT_RD)

    def close(self):
        pass

    def handle_read(self, data):
        raise NotImplementedError

    def handle_write(self, bytes_sent):
        pass

    def handle_error(self, err):
        raise NotImplementedError
        
    @property
    def read_buffer_size(self):
        return self._read_buffer_size

    @read_buffer_size.setter
    def read_buffer_size(self, buffer_size):
        self._read_buffer_size = buffer_size
    
    def async_write(self, data):
        self._data_to_write += data
        self._loop.register(self._sock, self, EventLoop.WRITE_EVENT)
    
    def onRead(self, e):
        try:
            data = self._sock.recv(self._read_buffer_size)
        except (IOError, OSError) as err:
            if getattr(err, 'errno', None) in [errno.EAGAIN, errno.EWOULDBLOCK, errno.ETIMEDOUT]:
                pass
            else:
                self.handle_error(err)
            return

        self.handle_read(data)

    def onWrite(self, e):
        try:
            bytes_sent = self._sock.send(self._data_to_write)
            self._data_to_write = self._data_to_write[bytes_sent:]
            if len(self._data_to_write) == 0:
                self._loop.unregister(self._sock, EventLoop.WRITE_EVENT)
        except (IOError, OSError) as err:
            if getattr(err, 'errno', None) in [errno.EAGAIN, errno.EWOULDBLOCK, errno.EINPROGRESS]:
                pass
            else:
                self.handle_error(err)
            return

        self.handle_write(bytes_sent)

        if self._closing and len(self._data_to_write) == 0:
            self.close()

class AsyncUDPHandler(EventHandler):
    BUFFER_SIZE = 14336

    def __init__(self, loop, sock):
        self._loop = loop
        self._sock = sock
        self._data_to_write = []
        self._read_buffer_size = AsyncUDPHandler.BUFFER_SIZE
        self._closing = False

        self._loop.register(self._sock, self, EventLoop.READ_EVENT)

    def close_gracefully(self):
        if len(self._data_to_write) == 0:
            self.close()
        else:
            self._closing = True
            self._sock.shutdown(socket.SHUT_RD)

    def close(self):
        pass

    def handle_read(self, data, addr):
        raise NotImplementedError

    def handle_write(self, addr, bytes_sent):
        pass

    def handle_error(self, err):
        raise NotImplementedError
        
    @property
    def read_buffer_size(self):
        return self._read_buffer_size

    @read_buffer_size.setter
    def read_buffer_size(self, buffer_size):
        self._read_buffer_size = buffer_size
    
    def async_write(self, data, addr):
        self._data_to_write.append((data, addr))
        self._loop.register(self._sock, self, EventLoop.WRITE_EVENT)
    
    def onRead(self, e):
        try:
            data, addr = self._sock.recvfrom(self._read_buffer_size)
        except (IOError, OSError) as err:
            if getattr(err, 'errno', None) in [errno.EAGAIN, errno.EWOULDBLOCK, errno.ETIMEDOUT]:
                pass
            else:
                self.handle_error(err)
            return

        self.handle_read(data, addr)

    def onWrite(self, e):
        try:
            data, addr = self._data_to_write[0]
            bytes_sent = self._sock.sendto(data, addr)
            del self._data_to_write[0]
            if len(self._data_to_write) == 0:
                self._loop.unregister(self._sock, EventLoop.WRITE_EVENT)
        except (IOError, OSError) as err:
            if getattr(err, 'errno', None) in [errno.EAGAIN, errno.EWOULDBLOCK, errno.EINPROGRESS]:
                pass
            else:
                self.handle_error(err)
            return

        self.handle_write(addr, bytes_sent)

        if self._closing and len(self._data_to_write) == 0:
            self.close()
