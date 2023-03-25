#!/bin/bash

action=${1}
iface=${2}

if [ "$action" == "start" ]; then
    sudo ifconfig $iface down
    sudo iwconfig $iface mode monitor
    sudo ifconfig $iface up

    exit

elif [ "$action" == "stop" ]; then
    sudo ifconfig $iface down
    sudo iwconfig $iface mode managed
    sudo ifconfig $iface up

    exit
fi

sudo iwconfig $iface 2>&1 | grep "Monitor " > /dev/null
