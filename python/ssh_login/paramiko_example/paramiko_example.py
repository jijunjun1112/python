#!/usr/bin/env python
# -*- coding: utf-8 -*-

import paramiko
import re

###获取单板shell命令结果###
def GetShellResult(usr,pwd,host,port,cmd):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, int(port), usr, pwd)
    stdin,stdout,stderr = ssh.exec_command(cmd)
    # print stdout.readlines("")
    b = stdout.readlines("")
    print b
    print type(b)
    for i in range(len(b)):
        print b[i]
    ssh.close()
    return b


###获取分级存储配置项###
###返回项依次是：VodHitDataNum，VodHitGritNum，VodHitGritTime，VodHitTime，VodHotNum，MaxVodHotNum，VodColdNum###
def GetSSDConfig(usr,pwd,host,port):
    result = []
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, int(port), usr, pwd)
    cmd_VodHit= 'grep ^VodHit* /home/config.ini;grep ^VodHotNum /home/config.ini;grep ^MaxVodHotNum /home/config.ini;grep ^VodColdNum /home/config.ini'
    stdin,stdout,stderr  = ssh.exec_command(cmd_VodHit)
    config_pattern = re.compile(r'=(\d+)')
    a = stdout.readlines("")
    print a, type(a)
    for eachconfig in range(len(a)):
        VodHit = config_pattern.findall(a[eachconfig])
        print VodHit, type(VodHit)
        result.append(int(VodHit[0]))
    ssh.close()
    print result

# GetSSDConfig("root","123456","192.168.121.130","22")
# GetShellResult("root","123456","192.168.121.130","22","ls")
GetShellResult("root","123456","192.168.121.127","22","tail -5 /data/opensips/logs/opensips.log")
