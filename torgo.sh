#!/bin/bash

while getopts ":o:d:" opt; do
  case ${opt} in
    o)
      variable=$(masscan -p 443 $OPTARG | grep "Discovered open port" | cut -d " " -f 6)
      for line in $variable;
      do
        nmap -p 443 --script ssl-cert $line | grep "ssl-cert" | grep -Po "(?<=organizationName=)[^,]*" | cut -d "/" -f 1
      done
      ;;
    d)
      variable=$(masscan -p 443 $OPTARG | grep "Discovered open port" | cut -d " " -f 6)
      for line in $variable;
      do
        nmap -p 443 --script ssl-cert $line | grep "ssl-cert" | grep -Po "(?<=commonName=)[^,]*" | cut -d "/" -f 1
        sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
    N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
    openssl x509 -noout -text -in <(
        openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
            -connect $line:443 ) ) | grep "DNS:" | cut -d ":" -f 2
      done
      ;;

    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

