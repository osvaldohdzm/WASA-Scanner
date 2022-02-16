#!/bin/bash


while getopts h:p:i: flag
do
    case "${flag}" in
        h) hostname=${OPTARG};;
        p) port=${OPTARG};;
        i) ip=${OPTARG};;
    esac
done

output_name="`date +"%Y-%m-%d"`-${hostname}-${port}-${ip}.txt"
echo "Writing output: $output_name"

echo "########################" >> $output_name
echo "Testing SSL/TLS"
sslscan $hostname:$port
read -r -p "Press any key to continue..." key

echo "########################" >> $output_name
echo "Testing Referer Header"
python3 PythonScripts/RefererHeaderTest.py --host "http://${hostname}" 
python3 PythonScripts/RefererHeaderTest.py --host "https://${hostname}"
read -r -p "Press any key to continue..." key

echo "########################" >> $output_name
echo "Testing Host Header Inyection"
python3 PythonScripts/HostHeaderTest.py --host "http://${hostname}" >> tmp.txt
python3 PythonScripts/HostHeaderTest.py --host "https://${hostname}" >> tmp.txt
fgrep --color -E '^|evil|evil-site.com' tmp.txt >> tmp_formated.txt
cat tmp_formated.txt >> $output_name
rm tmp.txt tmp_formated.txt
read -r -p "Press any key to continue..." key

echo "########################" >> $output_name

