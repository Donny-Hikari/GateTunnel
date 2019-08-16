#!/bin/bash

lan_network=10.0.0.0/24
target=10.0.0.192/27
tcp_server=10.0.0.2:32822
udp_server=10.0.0.2:32823

print_usage()
{
    echo "Usage"
    echo "  $(basename $(readlink -f $0)) [setup(s) [--bypass-lan] [--bypass-dns]|clear(c)|help(h)]"
}

iptables_noerr()
{
    sudo iptables $@ 2>/dev/null
}

setup()
{
    for k in "$@"; do
        if [[ $k == "--bypass-lan" ]]; then
            bypass_lan=1
        elif [[ $k == "--bypass-dns" ]]; then
            bypass_dns=1
        fi
    done

    echo "[net-settings] sysctl"
    sudo sysctl net.ipv4.ip_forward=1

    echo 

    if [[ $bypass_lan == 1 ]]; then
        iptables_noerr -t nat -A PREROUTING --src $target --dst $lan_network -j ACCEPT
    fi
    if [[ $bypass_dns == 1 ]]; then
        iptables_noerr -t nat -A PREROUTING -p udp --src $target --dport 53 -j ACCEPT
    fi
    iptables_noerr -t nat -A PREROUTING -p udp --src $target -j DNAT --to $udp_server
    iptables_noerr -t nat -A PREROUTING -p tcp --src $target -j DNAT --to $tcp_server
    iptables_noerr -t nat -A POSTROUTING -j MASQUERADE

    echo "[net-settings] iptable on table \"nat\":"
    sudo iptables -t nat -L
}

clear()
{
    sudo sysctl net.ipv4.ip_forward=0

    iptables_noerr -t nat -D PREROUTING --src $target --dst $lan_network -j ACCEPT
    iptables_noerr -t nat -D PREROUTING -p udp --src $target --dport 53 -j ACCEPT
    iptables_noerr -t nat -D PREROUTING -p udp --src $target -j DNAT --to $udp_server
    iptables_noerr -t nat -D PREROUTING -p tcp --src $target -j DNAT --to $tcp_server
    iptables_noerr -t nat -D POSTROUTING -j MASQUERADE

    echo "[net-settings] iptable on table \"nat\":"
    sudo iptables -t nat -L
}

case $1 in
    s|setup)
    setup "$@"
    ;;
    c|clear)
    clear
    ;;
    h|help|*)
    print_usage
    ;;
esac
