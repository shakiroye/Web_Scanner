#!/usr/bin/env python3
# coding:utf-8

import web_scanner

ws = web_scanner.WebScanner("http://192.168.0.47/mutillidae/")
ws.check_sqli("http://192.168.0.47/mutillidae/index.php?page=user-info.php")
ws.check_xss_form("http://192.168.0.47/mutillidae/index.php?page=user-info.php")
ws.check_xss_link("http://192.168.0.47/mutillidae/index.php?page=user-info.php")
ws.get_login_session({"username":"admin","password":"password","Login":"Login"})
print(ws.get_page_source("http://192.168.0.47/dvwa/"))