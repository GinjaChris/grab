#I basically took this script: https://github.com/Beek-Kefyalew/Python-Banner-Grabber/blob/master/bannerGrab.py
#Then improved(?) it and made it work with Python3
import socket
socket.setdefaulttimeout(2.5)
import argparse
import requests
import json
import urllib3
urllib3.disable_warnings()
import ssl

parser = argparse.ArgumentParser("usage: grab.py [options]")
parser.add_argument("-d", dest="dest", required=True, help="[required] specify destination IP or hostname")
args = parser.parse_args()
dest = args.dest
destip = socket.gethostbyname(dest)

def certgrab(dest, port):
	context = ssl.create_default_context()
	try:
		with socket.create_connection((dest, port)) as sock:
			with context.wrap_socket(sock, server_hostname=dest) as sslsock:
				der_cert = sslsock.getpeercert(True)
				pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
				print("\n")
				print("Public certificate PEM is:","\n")
				print(pem_cert)
	except:
		print("Failed to grab the certificate")
		return
			
			
def ReturnBanner(dest, port):
	try:
		sock = socket.socket()
		sock.connect((dest, port))
		banner = sock.recv(1024)
		return banner
	except: 
		return
	
		
def main():
	headers = {
	"Host": dest,
	"Connection": "Close",
	}
	
	IP = ("host IP: "+destip)
	print("\n","Attempting to grab banners, headers and certs from common ports on "+IP)

	PortList = [21, 22, 23, 25,80,110,443]
	PortNames = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 110: "pop3", 443: "https"}

	for port in PortList:
		banner = ReturnBanner(dest, port)
		if port == 80 or port == 443:
			try:
				print("\n","[ + ] Response headers from "+str(PortNames[port])+" port:","\n")
				response=requests.head(str(PortNames[port])+"://"+dest, headers=headers, timeout=3, verify=False)
				print(response.status_code, response.reason)
				print(response.headers)
			except: 
				print("[ - ] Something went wrong....probably the server didn't respond correctly to our "+str(PortNames[port])," request","\n")
				continue
		else:	
			if  banner:
				print("\n","[ + ] Result for "+str(PortNames[port])+":","\n"+str(banner),"\n")
			else:
				print("\n","[ - ] Unable to connect via "+str(PortNames[port]),"port","\n")		
	if port == 443:
		certgrab(dest, port)
	
if __name__ == '__main__':
 main()
	

