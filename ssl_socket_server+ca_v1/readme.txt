1.data.py作为模拟xmeetings.ipvideotalk.com的服务器
2.注意要在hosts文件中加上192.168.126.58【tab】xmeetings.ipvideotalk.com,这样才能使得xmeetings.ipvideotalk.com不需要使用dns解析，而直接定位到本机local的ip地址：192.168.126.58。hosts文件地址：C:\Windows\System32\drivers\etc
3.test.key和test.pem为一对证书密钥和证书
4.如果使用firefox作为客户端，则在加会的时候，重定向为访问https://xmeetings.ipvideotalk.com:10080/会提示此链接不安全（在日志中），此时需要导入数字证书。
5.导入数字证书的方法：设置setting---->证书---->查看证书---->证书机构---->导入，或者服务器---->添加例外，输入https://xmeetings.ipvideotalk.com:10080/，获取证书。
6.期间可能需要修改dns为线上，先获取一次线上的证书，然后再修改为本地的dns，进行加会
7.直接在firefox地址url输入：https://xmeetings.ipvideotalk.com:10080，有的时候会很久都没法响应，有的时候在地址栏左端出现红色或者绿色，绿色代表成功。