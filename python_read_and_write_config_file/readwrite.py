import ConfigParser
import sys,os

def read_ini(config_file_path, field, key):  
    cf = ConfigParser.ConfigParser()  
    cf.read(config_file_path)  

    s = cf.sections()   
#    print 'section:', s  
#    o = cf.options(field )  
#    print 'options:', o
#    v = cf.items(field)   
#        print 'items:', v
    config_result = cf.get(field, key)
    return config_result

def wirte_ini(config_file_path, field, key,value):
    cf = ConfigParser.ConfigParser()  
    cf.read(config_file_path)
#    print f
    cf.set(field, key, value)  
    cf.write(open(config_file_path, "w"))
    
    # -*- coding: cp936 -*-
def Get_cur_dir():
    '''     
     path = sys.path[0]
     if os.path.isdir(path):
         return path
     elif os.path.isfile(path):
         return os.path.dirname(path)
    '''
    path_sys = sys.path[0]
#    print path_sys
#    path = os.path.dirname(path_sys)
    path = os.path.split(os.path.realpath(__file__))[0]
#    print os.path.abspath('.')
    
    return path 

def main():
    print read_ini('MeetingInfo.ini', 'meetingInfo', 'hostid')
    wirte_ini('MeetingInfo.ini', 'meetingInfo', 'test','testvalue')
    print read_ini('MeetingInfo.ini', 'meetingInfo', 'test')
    print Get_cur_dir()
    path=Get_cur_dir()+'\MeetingInfo.ini'
    print path
    print read_ini(path, 'meetingInfo', 'hostid')

if __name__ == '__main__':
	main()