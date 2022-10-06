#!/bin/bash

sleep 4
echo "Trafico normal"
wget -q -O - https://www.stackoverflow.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
sleep 3
echo "Trafico ilicito"
wget -q -O - https://www.nytimes.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
echo "Trafico normal"
wget -q -O - https://www.stackoverflow.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
echo "Trafico ilicito"
wget -q -O - https://www.nytimes.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
sleep 5
echo "Trafico normal"
wget -q -O - https://www.stackoverflow.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
echo "Trafico normal"
wget -q -O - https://www.stackoverflow.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
echo "Trafico ilicito"
wget -q -O - https://www.nytimes.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
sleep 2
echo "Trafico normal"
wget -q -O - https://www.stackoverflow.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
echo "Trafico ilicito"
wget -q -O - https://www.nytimes.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
echo "Trafico ilicito"
wget -q -O - https://www.nytimes.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
sleep 4
echo "Trafico normal"
wget -q -O - https://www.stackoverflow.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
echo "Trafico ilicito"
wget -q -O - https://www.nytimes.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
sleep 3
echo "Trafico normal"
wget -q -O - https://www.stackoverflow.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
echo "Trafico normal"
wget -q -O - https://www.stackoverflow.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
echo "Trafico ilicito"
wget -q -O - https://www.nytimes.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
sleep 1
echo "Trafico normal"
wget -q -O - https://www.stackoverflow.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
echo "Trafico normal"
wget -q -O - https://www.stackoverflow.com/ --header 'Host: stackoverflow.com' | 2>/dev/null
echo""
echo "///////////////////////////////////////////"
echo "Trafico normal: 10"
echo "Trafico enmascarado (Domain Fronting): 7"
echo "//////////////////////////////////////////"
