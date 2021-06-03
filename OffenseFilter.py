
# This script takes Rule ID as argument
# Return Offenses ID where this Rule contributed in
# The returned Offenses ID are written in the file named "OffensesID.text"
# Use the next scrcipt (OffenseClose.py) to close these Offenses



import requests
import urllib3
import sys



if len(sys.argv) < 2:
	print("Usage: "+sys.argv[0]+" [RuleID]")
	print("Example: "+sys.argv[0]+" 104338")
	exit()



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Config
ip = '192.168.1.40'
token = '1abcdefg-2hij-345k-lmno-pqrstuvwxyza'
headers = {'Version': '12.1', 'Accept': 'application/json', 'SEC': token}
RuleID = sys.argv[1]


r = requests.get('https://'+str(ip)+'/api/siem/offenses?fields=id%2Cdescription%2Crules(id)&filter=status%3D%22OPEN%22',verify=False,headers=headers)


for offense in r.json():
    if offense['rules'][0]['id'] == int(RuleID):
    	print(offense['id'])
    	with open('OffensesID.text', 'a') as file:
    		file.write(str(offense['id'])+'\n')
        
