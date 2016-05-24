1.cert.pem和key.pem为一对，证书与密钥
2.test.key和test.pem为一对，证书与密钥，公司中使用的ipvt
3.ssl_client.py为客户端，ssl_server.py为服务端，先运行服务端，再运行客户端，注意两个代码文件中的证书与密钥需要匹配
4.服务端需要注明cert.pem和key.pem，而客户端需要注明cert.pem
5.如果客户端注明的是test.pem，与服务端是不匹配的证书，
那么客户端报错：ssl.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed (_ssl.c:590)
服务端报错：ssl.SSLError: [SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca (_ssl.c:590)
若出现如上两个错误，则说明是证书不匹配导致的。