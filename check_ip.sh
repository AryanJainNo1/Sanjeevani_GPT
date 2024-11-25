#!/bin/bash
echo "IPv4 Address:"
curl -4 icanhazip.com

echo -e "\nDetailed Network Information:"
ip -4 addr show

echo -e "\nNetwork Interfaces:"
ifconfig | grep inet 