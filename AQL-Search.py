# This script will do:
# - Takes AQL query .
# - Sends the query to Qradar.
# - Checks & waits for the query to be completed.
# - Generates CSV file contains the query result.
# - Sends email to the specified email contains the generated CSV file as an attachment.
# This script supposed to overcome the Qradar scheduling restriction of generating reports
# where it can be run every 3 hours instead of every hour for example.
# It could be run as a cron job.

import requests
import urllib3
import time
import csv
import smtplib
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from email import encoders




# Avoid TLS warning on terminal
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Config
ip = '192.168.1.20' # Qradar IP Address
token = '1abcdefg-2hij-345k-lmno-pqrstuvwxyza' # Qradar Token (Created from Admin Tab of Qradar)
gmail_username = 'mygmailusername' # Gmail Account, Make Sure "Less secure app access" is Enabled
gmail_password = 'P@$$w0rd'
sender_name = 'TED SIEM'
receiver_mail = 'soc@comp.eg'
mail_subject = 'WAF Denied Attacks Last 12 Hours'
file_name = 'waf_denied_attacks_last_12.csv' # CSV File Will be Created with This Name (If NOT Exist)
time_to_wait = 30 # Waiting Time to Check for Query Completion Status


headers = {'Version': '12.1', 'Accept': 'application/json', 'SEC': token}

# AQL Query
query = '''
SELECT DATEFORMAT(starttime, 'YYYY-MM-dd, hh:mm:ss') AS 'Time Stamp', "F5_Action" AS 'WAF Action', QIDNAME(qid) AS 'Event Name', 
sourceIP AS 'SRC IP', sourcepORt AS 'SRC Port',
destinationIP AS 'DST IP', destinationPort AS 'DST Port', 
logsourcename(logsourceid) AS 'Log Source', 
CATEGORYNAME(categORy) AS 'Category', 
userName AS 'Username', 
MAX("magnitude") AS 'Magnitude (Maximum)', 
SUM("eventCount") AS 'Event Count (Sum)', 
COUNT(*) AS 'Count' from events 
where (  F5_Action = 'blocked' AND logSourceId = '1127' ) 
	AND (eventDirection = 'L2R' or eventDirection = 'L2L')
GROUP BY sourceIP 
order by "Count" desc 
LIMIT 1000 
last 12 hours
'''


# CSV Function To Generate CSV File
def toCSV():
	data = r.json()
	events = data['events'] 
	data_file = open(file_name, 'w') 
	csv_writer = csv.writer(data_file)
	count = 0
	for event in events: 
	    if count == 0: 
	        header = event.keys() 
	        csv_writer.writerow(header) 
	        count += 1 
	    csv_writer.writerow(event.values()) 
	data_file.close() 
	return True



# Gmail Function To Send Mail With The Attachment
def send_gmail(send_to, subject, message, files=[]):
    send_from = sender_name
    server='smtp.gmail.com'
    port=587
    username= gmail_username
    password= gmail_password
    use_tls=True
    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = send_to
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach(MIMEText(message))
    for path in files:
        part = MIMEBase('application', "octet-stream")
        with open(path, 'rb') as file:
            part.set_payload(file.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition',
                        'attachment; filename="{}"'.format(Path(path).name))
        msg.attach(part)
    smtp = smtplib.SMTP(server, port)
    if use_tls:
        smtp.starttls()
    smtp.login(username, password)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.quit()





# Send AQL query
print('[+] Sending Your Query...')
r = requests.post('https://'+ip+'/api/ariel/searches?query_expression='+query,verify=False,headers=headers)
print('[+] Waiting '+str(time_to_wait)+' Seconds For The Query Result...')
time.sleep(time_to_wait)
search_id = r.json()['search_id']


while True:
	# Check the query status
	print('[*] Checking The Query Status...')
	r = requests.get('https://'+ip+'/api/ariel/searches/'+search_id,verify=False,headers=headers)
	status = r.json()['status']
	if status == 'COMPLETED' :
		print('[+] Search Completed...')
		print('[+] Retreiving Search Result...')
		r = requests.get('https://'+ip+'/api/ariel/searches/'+search_id+'/results',verify=False,headers=headers)
		if toCSV():
			send_gmail(receiver_mail, mail_subject, '', files=[file_name])
			print('[+] Success')
		exit()
	else:
		print('[-] Search is Not Completed, Waiting '+str(time_to_wait)+' Seconds...')
		time.sleep(time_to_wait)



