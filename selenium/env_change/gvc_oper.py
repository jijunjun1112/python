#coding:utf-8
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains #引入ActionChains鼠标操作类
from selenium.webdriver.common.keys import Keys #引入keys类操作
import time
import sys

dns4= sys.argv[1]
# dns4= 120
browser = webdriver.Firefox()
def openBrowser():
	browser.get('http://192.168.126.105/')
	browser.maximize_window() 
	time.sleep(3) 

def login():
	browser.find_element_by_id('username').send_keys(u'admin')
	browser.find_element_by_class_name('password').send_keys(u'admin')
	browser.find_element_by_id('loginbtn').click() 
	time.sleep(2)

def correctDNS():
	browser.find_element_by_id('advset_menu').click() 
	browser.find_element_by_class_name('m_advavset_net').click()
	time.sleep(2)
	frame = browser.find_element_by_xpath('.//*[@id="iframediv"]')
	browser.switch_to_frame(frame)
	browser.find_element_by_id('prednsser4').clear()
	browser.find_element_by_id("prednsser4").send_keys(dns4)
	browser.find_element_by_id('a_save').click() 
	time.sleep(2)
	browser.switch_to_default_content()

def applyDNS():
	browser.find_element_by_id('advset_menu').click()
	time.sleep(1)
	browser.find_element_by_xpath(".//*[@id='account2_general']").click()
	time.sleep(2)

	frame = browser.find_element_by_xpath('.//*[@id="iframediv"]')
	browser.switch_to_frame(frame)
	browser.find_element_by_xpath('.//*[@id="enableiptalkpro"]').click()
	time.sleep(1)
	browser.find_element_by_id('a_save').click() 
	time.sleep(2)
	browser.switch_to_default_content()
	browser.find_element_by_id('apply').click()
	time.sleep(10)

	frame = browser.find_element_by_xpath('.//*[@id="iframediv"]')
	browser.switch_to_frame(frame)
	browser.find_element_by_xpath('.//*[@id="enableiptalkpro"]').click()
	time.sleep(1)
	browser.find_element_by_id('a_save').click() 
	time.sleep(2)
	browser.switch_to_default_content()
	browser.find_element_by_id('apply').click()
	time.sleep(10)

	browser.quit()
	

def main():
	openBrowser()
	login()

	if browser.find_element_by_id('incomingcall').is_displayed():
		frame = browser.find_element_by_xpath('.//*[@id="incomingcall"]')
		browser.switch_to_frame(frame)
		browser.find_element_by_id('close').click() 

	correctDNS()
	applyDNS()

	print "Has already changed the gvc dns!!\n"





if __name__ == '__main__':
	main()

