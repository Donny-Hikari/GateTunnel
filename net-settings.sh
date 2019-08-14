#!/bin/bash

target=10.0.0.192/27
tcp_server=10.0.0.2:32822
udp_server=10.0.0.2:32823

print_usage()
{
    echo "Usage"
    echo "  $(basename $(readlink -f $0)) [setup(s)|clear(c)|help(h)]"
}

iptables_add_not_exist()
{
    sudo iptables -C $@ 1>/dev/null 2>&1
    if [[ $? != 0 ]]; then
        sudo iptables -A $@
    fi
}

setup()
{
    sudo sysctl net.ipv4.ip_forward=1

    iptables_add_not_exist PREROUTING -t nat -p udp --src 10.0.0.192/27 -j DNAT --to $udp_server
    iptables_add_not_exist PREROUTING -t nat -p tcp --src 10.0.0.192/27 -j DNAT --to $tcp_server
    iptables_add_not_exist POSTROUTING -t nat -j MASQUERADE
}

clear()
{
    sudo sysctl net.ipv4.ip_forward=0

    sudo iptables -D PREROUTING -t nat -p udp --src 10.0.0.192/27 -j DNAT --to $udp_server
    sudo iptables -D PREROUTING -t nat -p tcp --src 10.0.0.192/27 -j DNAT --to $tcp_server
    sudo iptables -D POSTROUTING -t nat -j MASQUERADE
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
