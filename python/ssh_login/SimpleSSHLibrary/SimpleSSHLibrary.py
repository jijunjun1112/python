#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: JiaSongsong
# Date: 2016-02-03

import sys, time, os
from subprocess import Popen, PIPE


CONFIRM_TEXT = 'Store key in cache? (y/n)'


def get_cur_dir():
    return os.path.split(os.path.realpath(__file__))[0] + os.path.sep


class SimpleSSHLibrary(object):
    def __init__(self):
        self._interval = 0.01  # 10ms
        #print self._interval
        self._set_exec_right()

    def exec_cmd(self, usr, pwd, host, cmd, port=22):
        """通过SSH执行远程命令.

        Parameters:
            - usr - ssh登陆远程主机使用的用户名
            - pwd - ssh登陆远程主机使用的密码
            - host - 远程主机的IP
            - cmd - 要执行的命令
            - port - [可选参数]指定ssh登陆的端口，默认22端口
        Example:
            | exec_cmd | usr | pwd | host | cmd | port=22 |
            | exec_cmd | root | zxiptv | 10.17.161.66 | ls -l |  |
        """
        cmd = '{ssh} -ssh -P {port} -pw {pwd} {usr}@{host} "{cmd}"'.format(
            ssh=self._get_plink(),
            port=port,
            pwd=pwd,
            usr=usr,
            host=host,
            cmd=cmd)
        success, result = self._exec_cmd(cmd)
        return success, result

    def scp(self, src_uri, dst_uri, usr, pwd, port=22):
        """在本地执行scp拷贝命令.

        Parameters:
            - src_uri - 源文件URI
            - dst_uri - 目的文件URI
            - usr - scp使用的用户名
            - pwd - scp使用的密码
            - port - [可选参数]指定scp端口，默认22端口
        Example:
            | scp | src_uri | dst_uri | usr | pwd | port=22 |
            | scp | 10.17.161.66:/tmp/ts.cap | . | root | zxiptv |  |
        """
        cmd = r'{scp} -P {port} -l {usr} -pw {pwd} -r "{src}" "{dst}"'.format(
            scp=self._get_pscp(),
            usr=usr,
            pwd=pwd,
            port=port,
            src=src_uri.replace('\\', '/'),
            dst=dst_uri.replace('\\', '/'))
        success, result = self._exec_cmd(cmd)
        return success, result

    def _get_bin_path(self):
        return get_cur_dir() + 'bin' + os.path.sep

    def _get_plink(self):
        return self._get_bin_path() + 'plink'

    def _get_pscp(self):
        return self._get_bin_path() + 'pscp'

    def _set_exec_right(self):
        #print os.name  #nt
        if os.name == 'posix':  #means:linux os
            cmd = 'chmod +x {} {}'.format(self._get_plink(), self._get_pscp())
            #print cmd
            os.system(cmd)  #??

    def _communicate(self, ssh, cmd=None):
        (stdoutdata, stderrdata) = ssh.communicate(cmd)
        # 首次登陆忽略询问消息
        #print stdoutdata
        #print stderrdata
        if CONFIRM_TEXT in stderrdata:
            stderrdata = ''
        return stdoutdata + stderrdata

    def _exec_cmd(self, cmd):
        ssh = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        result = self._communicate(ssh, 'y')
        #print ssh.returncode   #0
        return 0 == ssh.returncode, result


if __name__ == '__main__':
    # print get_cur_dir()  #D:\cgi-bin\
    # print __file__  #SimpleSSHLibrary.py
    # print os.path.realpath(__file__)    #D:\cgi-bin\SimpleSSHLibrary.py
    # print os.path.split(os.path.realpath(__file__))[0] + os.path.sep #D:\cgi-bin\
    # print os.path.sep
    # print os.path.split(os.path.realpath(__file__))
    ssh = SimpleSSHLibrary()
    #print ssh.exec_cmd('root', 'zxiptv', '10.17.161.66', 'ls')
    #print ssh.exec_cmd('root', 'cgsl123', '172.16.6.75', 'ls')
    #print ssh.exec_cmd('root', 'cgsl123', '172.16.6.75', "grep \'Process Successful\'  /mnt/ZMSS/ZMSSMediaFile.log| tail -1 ")
    # print ssh.exec_cmd('root', 'cgsl123', '172.16.6.75', "sed -i 's#\"Max_Copy_Session_Number\" TYPE=\"\" >.*<#\"Max_Copy_Session_Number\" TYPE=\"\" >40<#g' /ZMSS/etc/streamingserver.xml")
    #print ssh.scp('10.17.161.57:/tmp/index.idx', '.', 'root', 'zxiptv')
    #print ssh.scp('172.16.6.6:/tmp/index.idx', '.', 'root', 'cgsl123')#iptv is 172.16.6.6 password
    print ssh.exec_cmd('root', '123456', '192.168.121.130', 'ls')
