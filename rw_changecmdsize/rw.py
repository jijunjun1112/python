#-*- encoding:UTF-8 -*-
filestr="c:\\eee\\cmd.bat"
f = open(filestr,'wb')
f.write("")
f.close()

COLS=0
LINES=0
f = open(filestr,'wb')
for x in xrange(1,100):
	new_context="cmd /c MODE con: COLS="+str(COLS)+" LINES="+str(LINES)+"\nping -n 3 127.0.0.1\n"
	COLS+=3
	LINES+=1
	f.write(new_context)
f.close()

filehandler = open(filestr,'rb')  #以读方式打开文件，rb为二进制方式(如图片或可执行文件等) 
filehandler.seek(0)
textlist = filehandler.readlines()
for line in textlist:
    print line,
print
filehandler.close()                  #关闭文件句柄