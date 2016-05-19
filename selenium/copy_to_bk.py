#coding:utf-8
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains #引入ActionChains鼠标操作类
from selenium.webdriver.common.keys import Keys #引入keys类操作
import time
import sys
import ctypes


def openBrowser():
	global browser
	browser = webdriver.Firefox()
	browser.get('http://i.cnblogs.com/EditPosts.aspx?opt=1')
	browser.maximize_window() 
	time.sleep(2) 

def login():
	browser.find_element_by_id('input1').send_keys(u'jijunjun1112')
	browser.find_element_by_id('input2').send_keys(u'Jun13676830606!')
	browser.find_element_by_id('signin').click() 
	time.sleep(1)

def copyCode(): 
	CF_TEXT = 1
	kernel32 = ctypes.windll.kernel32
	user32 = ctypes.windll.user32

	user32.OpenClipboard(0)
	if user32.IsClipboardFormatAvailable(CF_TEXT):
	    data = user32.GetClipboardData(CF_TEXT)
	    data_locked = kernel32.GlobalLock(data)
	    text = ctypes.c_char_p(data_locked)
	    print(text.value)
	    kernel32.GlobalUnlock(data_locked)
	else:
	    print('no text in clipboard') 
	user32.CloseClipboard()

def main():
	# openBrowser()
	# login()
	copyCode()

	#browser.quit()


if __name__ == '__main__':
	main()

