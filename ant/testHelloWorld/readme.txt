1.需要添加的是build.xml,里面是ant脚本用来编译、测试
2.在此目录下，输入ant命令：C:\Users\Administrator\workspace\testHelloWorld>ant
3.则生成hello1.jar,classes目录,.classpath等文件
4.可输入ant clear清除刚编译生成的文件
5.可输入ant rerun重新编译并运行


编译过程：
C:\Users\Administrator\workspace\testHelloWorld>ant
Buildfile: C:\Users\Administrator\workspace\testHelloWorld\build.xml

init:
    [mkdir] Created dir: C:\Users\Administrator\workspace\testHelloWorld\classes


compile:
    [javac] Compiling 1 source file to C:\Users\Administrator\workspace\testHell
oWorld\classes

build:
      [jar] Building jar: C:\Users\Administrator\workspace\testHelloWorld\hello1
.jar

run:
     [java] Hello world1

BUILD SUCCESSFUL
Total time: 3 seconds