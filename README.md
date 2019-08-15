
# GateTunnel

This program is for SCIENTIFIC RESEARCH purpose only. Please DO NOT use it for commercial purpose or use it in real life.

"Gateway" here refers to transparent proxy. (See [Proxy Server](https://en.wikipedia.org/wiki/Proxy_server#Transparent_proxy) on Wikipedia.)

## Why

The reason why we need a gateway proxy is that, neither http proxy nor VPN provides 100% proxy for all data traffic. For http proxy, the use is limited. On Android or PlayStation, the system or applications may ignore the http proxy settings. For VPN, you need system support or to install an application on the target system, which is sometimes difficult to achieve without root.

With GateTunnel, you can connect to proxy from any device so long as it support static IP address.

## Requirements

I develop and test this program on Linux with python 3.7. No additional library is required.

A SOCKS server is requried for this program to work, though. See section [SOCKS Server](#SOCKS-Server) for more information about SOCKS server.

## Run

First, setup your network using "net-setting.sh":

```shell
$ bash net-setting.sh
```

This setup requires administrator permission.

Then, start a SOCKS server, and then start the server:

```shell
$ python3 udp_tunnel_server.py
```

You can use "-c" to specify the configuration file location, and use "--verbose" or "--log-level $LOG_LEVEL" to specify the log level. "$LOG_LEVEL" should be an integer.

Finally, start the client:

```shell
$ sudo python3 gateway.py
```

You can use the "-c", "--verbose" and "--log-level" flags for the client as described above for the server.

Note that it requires administrator permission to start the client because it needs to monitor the network traffic.

Now, you can configure your device (any device that can connect to your LAN) to connect to the GateTunnel by:

1. Allocate an IP address that is in range of the target network (specified by the configuration file).

2. Set the gateway as the IP address of the machine that is running GateTunnel client.

3. Set a valid submask and a valid DNS.

Enjoy the magic!

## SOCKS Server

For this program to work, you need a SOCKS server, more specificially, a SOCKS5 server. The reason why I leave this part to you is that, this program is for SCIENTIFIC RESEARCH purpose only, not for generic use. So you may either code or find a SOCKS5 server yourself.

In fact, this program can work without a SOCKS5 server, with some modification on codes. But I leave this part to you, too.
