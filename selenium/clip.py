#coding:utf-8
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains 
from selenium.webdriver.common.keys import Keys 
import win32clipboard
import time

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

filehandler = open('C:\\Users\\Administrator\\login.py','r')                 
data=filehandler.read()  

# set clipboard data
win32clipboard.OpenClipboard()
win32clipboard.EmptyClipboard()
win32clipboard.SetClipboardText(data)
win32clipboard.CloseClipboard()


browser = webdriver.Firefox()
browser.get('http://i.cnblogs.com/EditPosts.aspx?opt=1')

browser.maximize_window() 
time.sleep(2) 

browser.find_element_by_id('input1').send_keys(u'jijunjun1112')
browser.find_element_by_id('input2').send_keys(u'Jun13676830606!')
browser.find_element_by_id('signin').click() 
time.sleep(1)

frame = browser.find_element_by_xpath('.//*[@id="Editor_Edit_EditorBody_ifr"]')
browser.switch_to_frame(frame)

print data
browser.find_element_by_id('tinymce').send_keys(data)
browser.switch_to_default_content()

browser.find_element_by_id('Editor_Edit_APOptions_Advancedpanel1_cklCategories_2').click()
browser.find_element_by_id('Editor_Edit_Advanced_chkDisplayHomePage').click()
browser.find_element_by_id('Editor_Edit_Advanced_chkComments').click()
browser.find_element_by_id('Editor_Edit_Advanced_chkMainSyndication').click()

browser.find_element_by_id('Editor_Edit_Advanced_tbEnryPassword').send_keys("1112")


# get clipboard data
win32clipboard.OpenClipboard()
data = win32clipboard.GetClipboardData()
win32clipboard.CloseClipboard()
print data