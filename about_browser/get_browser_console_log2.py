from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities  
import time  
# enable browser logging
d = DesiredCapabilities.FIREFOX
d['loggingPrefs'] = { 'server':'INFO' }
driver = webdriver.Firefox()
# load some site
# driver.get('http://www.baidu.com')
driver.get('https://meetings.ipvideotalk.com/364064441')
time.sleep(1) 
driver.find_element_by_name("userName").send_keys("ff") 
driver.find_element_by_name("email").send_keys("ff"+"@test.com")
driver.find_element_by_id("joinButton").click()
# print driver.log_types
# print driver.execute_script('document.title')
for x in xrange(1,10):
	
	time.sleep(15)
	# print messages
	print "=====================browser"
	for entry in driver.get_log('browser'):
	    for key,val in entry.items() :
	    	# print key
	    	if key == "message" :
	        	print val 
# print "=====================client"
# for entry in driver.get_log('client'):
#     for key,val in entry.items() :
#     	# print key
#     	if key == "message" :
#         	print val 

# print "=====================driver"
# for entry in driver.get_log('driver'):
#     for key,val in entry.items() :
#     	# print key
#     	if key == "message" :
#         	print val 

# print "=====================server"
# for entry in driver.get_log('server'):
#     for key,val in entry.items() :
#     	# print key
#     	if key == "message" :
#         	print val 