import smtplib
import string
import os
from time import strftime
import sys

ADDR_TO = 'to_address@email.com'
SMTP_SERVER = 'smtp.gmail.com'
 
SMTP_USERNAME = "from_address@gmail.com"
SMTP_PASSWORD = "password"
SUBJECT = "Intrusion Alert"

MAIL_TEMPLATE = """From: Raspberry Pi 
Subject: New Intrusion Alert from Raspberry Pi

Events list: 
"""
SRC_LOG = '/var/tmp/opencanary-tmp.log'
 
def lineCheck (srcevent):
     sendEmail = True 
     print("checking line > {}\n",srcevent) 

     srcIP        = findargs(srcevent,"src_host") 
     dstport = findargs(srcevent,"dst_port") 
     srcport      = findargs(srcevent,"src_port") 
     print("source IP: {}   destination port: {} \n".format(srcIP,dstport)) 
     if(srcIP =="127.0.0.1"):        
         if(dstport=="631"):            
             sendEmail = False       
     else:     
         if(srcIP == "192.168.1.101"):         
             if(dstport == "445") or (dstport == "139" ):            
                 sendEmail = False     
         else:         
             if(srcIP == "192.168.1.102"):             
                 if(dstport == "139"):                  
                      sendEmail = False 
     displaymsg = "{0}:{1} > {2}  ".format (srcIP,srcport,dstport)
     if (sendEmail):     
         displaymsg += '\033[31;40m UNKNOWN \033[37;40m\n' 
     else:     
         displaymsg += '\033[32;40m Ignored \033[37;40m\n' 
     
     f = open("/dev/tty1", "w")
     f.write(displaymsg)
     f.close() 
     return sendEmail

def findargs(srcevent,strcheck):
    res = ""
    checkStr = '"'+strcheck+'": "'
    chstart = srcevent.find(checkStr)
    if(chstart>0):
        chstart +=len(checkStr)
        chend =srcevent.find('"',chstart)
        if(chend>0):
            res = srcevent[chstart:chend]
        else:
            print("no end matching found \n")
    return res

def sendMail(emailmsg):
    sentEmail = False
    try:
        msg = MAIL_TEMPLATE + emailmsg
        server = smtplib.SMTP(SMTP_SERVER,587)
        server.ehlo()
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, ADDR_TO, msg)
        server.quit()
        sentEmail = True
    except:
        print("Log 'NOT' cleared. Can't send E-mail")
    return sentEmail

localtxt = ""
 

f2 = open(SRC_LOG,'r')
count  =0
for line in f2:
    if (lineCheck(line.strip())==True):
        count +=1
        localtxt += "Event {}: {}".format(count,line.strip())
        localtxt += "\n\r"
    else:
        print("ignoring line\n\r")
f2.close

if (count >0):
    emailsSent= sendMail(localtxt)
    if(emailsSent):
        f2 = open(SRC_LOG,'w')
        f2.writelines([])
        f2.close
