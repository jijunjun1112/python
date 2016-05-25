#!/bin/bash
#monitor available disk space
LOG_FILE="log.log"
`echo "-----start-----" > $LOG_FILE`
`touch $LOG_FILE`
SPACE=`df | sed -n '/\/$/p' | gawk '{print $5}'| sed 's/%//'`
while [[ $SPACE -ge 57 ]]; do
	DELETE_FILE=`ls -lr|sed -n '/opensips.log-/p'|sed -n '$p'|awk '{print $9}'`
	`rm -rf $DELETE_FILE`
	`echo "delete $DELETE_FILE" >> $LOG_FILE` 
	SPACE=`df | sed -n '/\/$/p' | gawk '{print $5}'| sed 's/%//'`
done
`mail -s 'monitor disk space' 317392058@qq.com < $LOG_FILE`
# if [ $SPACE -ge 55 ]
# then 
# `rm -rf $DELETE_FILE`
# fi
