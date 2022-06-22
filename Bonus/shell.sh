#!/bin/sh

echo "what is the server IP address ?"

read serverIP

echo $serverIP  > info.txt

echo "what is the target port number ?"

read serverPORT

echo $serverPORT  >> info.txt

echo "what is your interface IP address ?"

read interIP

echo $interIP  >> info.txt

echo "which port do you want to use ?"

read yourPORT

echo $yourPORT  >> info.txt

echo "what is your interface name ?"

read interNAME

echo $interNAME  >> info.txt

echo "what is your interface MAC address ?"

read interMAC

echo $interMAC  >> info.txt

echo "what is your gateway MAC address ?"

read gateMAC

echo $gateMAC  >> info.txt
