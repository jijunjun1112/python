#!/bin/bash
#script  to capture system statistics
OUTFILE=/home/xu/capstats.csv
DATE=`date +%m/%d/%Y`
TIME=`date +%k:%m:%s`
TIMEOUT=`uptime`
VMOUT=`vmstat 1 2 > log.log`
USERS=`echo $TIMEOUT | gawk '{print $6"\t"$7}' | sed 's/,//' `
LOAD=`echo $TIMEOUT | gawk '{print $10$11$12}' | sed 's/,/ /g' `
FREE=`sed -n '/[0-9]/p' log.log| sed -n '2p' | gawk '{print $4} ' `
IDLE=`sed -n '/[0-9]/p' log.log| sed -n '2p' |gawk '{print $15}' `
echo "$DATE,$TIME,$USERS,$LOAD,$FREE,$IDLE"
