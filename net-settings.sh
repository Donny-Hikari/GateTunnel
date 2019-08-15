#!/bin/bash

target=10.0.0.192/27
tcp_server=10.0.0.2:32822
udp_server=10.0.0.2:32823

print_usage()
{
    echo "Usage"
    echo "  $(basename $(readlink -f $0)) [setup(s)|clear(c)|help(h)]"
}

iptables_noerr()
{
    sudo iptables $@ 2>/dev/null
}

setup()
{
    sudo sysctl net.ipv4.ip_forward=1

    iptables_noerr -t nat -A PREROUTING -p udp --src 10.0.0.192/27 -j DNAT --to $udp_server
    iptables_noerr -t nat -A PREROUTING -p tcp --src 10.0.0.192/27 -j DNAT --to $tcp_server
    iptables_noerr -t nat -A POSTROUTING -j MASQUERADE
}

clear()
{
    sudo sysctl net.ipv4.ip_forward=0

    iptables_noerr -t nat -D PREROUTING -p udp --src 10.0.0.192/27 -j DNAT --to $udp_server
    iptables_noerr -t nat -D PREROUTING -p tcp --src 10.0.0.192/27 -j DNAT --to $tcp_server
    iptables_noerr -t nat -D POSTROUTING -j MASQUERADE
}

case $1 in
    s|setup)
    setup
    ;;
    c|clear)
    clear
    ;;
    h|help|*)
    print_usage
    ;;
esac
