# This script takes Offense ID as argumnet,
# Return the contributed Rules ID
# You can filter Offenses based on this contributed Rule ID (Use next script OffenseFilter.py)



import requests
import urllib3
import sys



if len(sys.argv) < 2:
	print("Usage: "+sys.argv[0]+" [OffenseID]")
	print("Example: "+sys.argv[0]+" 2500")
	exit()


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Config
ip = '192.168.1.40'
token = '1abcdefg-2hij-345k-lmno-pqrstuvwxyza'
headers = {'Version': '12.1', 'Accept': 'application/json', 'SEC': token}
OffenseID = sys.argv[1]



r = requests.get('https://'+str(ip)+'/api/siem/offenses/'+str(OffenseID),verify=False,headers=headers)
if r.status_code == 200:
	print("Offense ID : "+str(r.json()['id']))
	print("Description : "+str(r.json()['description']).rstrip())
	print("Status : "+str(r.json()['status']))
	for id in r.json()['rules']:
		print("Rule ID : " + str(id['id']))

else:
	print("Error!")
	exit()
