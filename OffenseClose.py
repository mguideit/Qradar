# This script takes text file as argument
# The text file suppose to have Offenses ID
# ID per line
# Return the status of closin the Offenses



import requests
import urllib3
import sys




if len(sys.argv) < 2:
	print("Usage: "+sys.argv[0]+" [IDsFile]")
	print("Example: "+sys.argv[0]+" /home/ahmed/OffensesID.text")
	exit()




urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Config
ip = '192.168.1.40'
token = '1abcdefg-2hij-345k-lmno-pqrstuvwxyza'
headers = {'Version': '12.1', 'Accept': 'application/json', 'SEC': token}
IDsFile = sys.argv[1]





with open(IDsFile) as file:
   IDs = file.readlines()
   for ID in IDs:
    r = requests.post('https://'+str(ip)+'/api/siem/offenses/'+ID+'?closing_reason_id=1&status=CLOSED',verify=False,headers=headers)
    if r.status_code == 200:
    	print(str(ID).rstrip()+" : Closed Successfully")
    elif r.status_code == 403:
    	print(str(ID).rstrip()+" : User does not have the required capability to perform the action.")
    elif r.status_code == 404:
    	print(str(ID).rstrip()+" : No offense was found for the provided offense_id.")
    elif r.status_code == 409:
    	print(str(ID).rstrip()+" : Request cannot be completed due to the state of the offense.")
    elif r.status_code == 422:
    	print(str(ID).rstrip()+" : A request parameter is not valid.")
    elif r.status_code == 500:
    	print(str(ID).rstrip()+" : An error occurred while the offense was being updated.")
    else:
    	print("Error!")



