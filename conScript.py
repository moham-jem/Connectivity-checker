import xml.dom.minidom, json, base64, getpass
import socket, sys, re, subprocess, os, paramiko, cmd

class sourceIPTesting:
	def __init__(self,srcNodeName,srcIP,destIPsColumn,destPortsColumn,destNodeNames,srcPassword):
		self.srcNodeName = srcNodeName
		self.srcIP = srcIP
		self.destIPs = destIPsColumn
		self.destPorts = destPortsColumn
		self.destNodeName = destNodeNames
		self.passwrd = srcPassword
				
	def testConnectivity(self):
		conMat=[]
		for destIP in self.destIPs:
			testResult=self.testPing(destIP)
			if destIP.find("\r") != -1:
				IP=str(destIP)[:-1]
			else:
				IP=str(destIP)
			for port in self.destPorts:
				if testResult == 0:
					#print("success")
					Line=[str(self.srcNodeName),str(self.srcIP) ,str(self.destNodeName), str(IP), "Pingable", self.checkPort(IP,port)]
					conMat.append(Line)
				elif testResult == 1 :
					#print("failed")
					Line=[str(self.srcNodeName),str(self.srcIP) ,str(self.destNodeName), str(IP), "Not Pingable", self.checkPort(IP,port)]
				conMat.append(Line)
		self.printMatrix(conMat)
	
	def updatePW(self, IP, PW):
		data=json.load(open("Dictpw.txt"))
		data[IP] = base64.b64encode(PW)
		json.dump(data, open("Dictpw.txt", "w"))
		print("Password for "+IP+" is updated.")
		
	def testPing(self,destIP):
		#Open SSH connection to get server type
		testResult=0
		count = 0
		try:
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh.connect(self.srcIP, username='root', password=str(self.passwrd))
		except paramiko.ssh_exception.AuthenticationException:
			self.passwrd=getpass.getpass("Root password for IP "+str(self.srcIP)+" is outdated, please re-enter it again: ")
			while checkPW(self.srcIP, self.passwrd) == "wrong" and count < 3:
				count+=1
				self.passwrd=getpass.getpass("Invalid password, please re-enter root password: ")
		if 0 < count < 3:
			self.updatePW(self.srcIP,self.passwrd)
		if count < 3:
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh.connect(self.srcIP, username='root', password=str(self.passwrd))
			stdin, stdout, stderr = ssh.exec_command("uname")
			output=stdout.readlines()
			#Construct the ping statement
			if str(output[0].split('\n')[0]) == "SunOS":
				pingStatement="ping "+destIP+" 1"
				stdin, stdout, stderr = ssh.exec_command(pingStatement)
				result = stdout.readlines()
				#Solaris Output Check
				if str(result[0].split("\n")[0]) != destIP+" is alive":
					testResult=1
			else:
				pingStatement="ping -w1 "+destIP
				stdin, stdout, stderr = ssh.exec_command(pingStatement)
				result = stdout.readlines()
				#Linux Output Check
				if str(result[1]) == '\n':
					testResult=1
			#Close the connection
			ssh.close()
		else:
			print("Invalid Password, please check later for IP "+self.srcIP)
			testResult=2
		return testResult
		
	def checkPort(self,IP,destPort):
		status=[]
		cmdString='''
		echo 'import socket
		import socket, sys, re
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(0.2)
		IP=sys.argv[1]
		port=sys.argv[2]
		try:
		 s.connect((IP, int(port)))
		 print("Port "+str(int(port))+" Success.")
		 s.close()
		except socket.error, e:
		 print("Port "+str(int(port))+" Failed ("+str(e)+" )")' > file'''
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(self.srcIP, username='root', password=self.passwrd)
		stdin, stdout, stderr = ssh.exec_command(cmdString)	     #Print mini-script to the source to check the ports     
		#Remove additional tab
		stdin, stdout, stderr = ssh.exec_command('cat file | tr -d "\t" > pyScrupt.py && rm -rf file')
		testLine="python pyScrupt.py "+IP+" "+destPort
		stdin, stdout, stderr = ssh.exec_command(testLine)		      #Run the mini-script
		output=stdout.readlines()
		if output != []:
			status.append(str(output).split("'")[1][:-2])
		stdin.close()
		return status

	def printMatrix(self, Matrix):
		spaces="			  "
		for row in Matrix:
			for ports in row[5]:
				if len(row[2]) < 12:
					dest=str(row[2])+spaces
				elif len(row[2]) < 15:
					dest=str(row[2])+"		"
				else:
					dest=str(row[2])
				if len(row[0]) < 12:
					src=str(row[0])+spaces
				else:
					src=str(row[0])
				line=[str(src)[0:15],row[1],str(dest)[0:18],row[3],row[4],ports]
				print '\t'.join(line)
#End of class Definition *whew*

#Parse XML File		     
def parseXML(file_path):
	#Parse XML file
	ComMatrix = xml.dom.minidom.parse(file_path)
	#Get number of rows and columns
	sheetRows_len=len(ComMatrix.getElementsByTagName('Worksheet')[0].getElementsByTagName('Table')[0].getElementsByTagName('Row'))
	sheetCols_len=len(ComMatrix.getElementsByTagName('Worksheet')[0].getElementsByTagName('Table')[0].getElementsByTagName('Row')[0].getElementsByTagName('Cell'))  
	for row_ele in range(1,sheetRows_len):
		#Get Source Node Name
		sourceNodeName=getText(ComMatrix.getElementsByTagName('Worksheet')[0].getElementsByTagName('Table')[0].getElementsByTagName('Row')[row_ele].getElementsByTagName('Cell')[0].getElementsByTagName('Data')[0].childNodes)
		#Get Source IPs
		srcIPs=getText(ComMatrix.getElementsByTagName('Worksheet')[0].getElementsByTagName('Table')[0].getElementsByTagName('Row')[row_ele].getElementsByTagName('Cell')[1].getElementsByTagName('Data')[0].childNodes)
		srcIPs_lined=srcIPs.split("&#10;")[0].split("\n")
		#Get Destination Ports
		destPorts=getText(ComMatrix.getElementsByTagName('Worksheet')[0].getElementsByTagName('Table')[0].getElementsByTagName('Row')[row_ele].getElementsByTagName('Cell')[2].getElementsByTagName('Data')[0].childNodes)
		destPorts_lined=destPorts.split("&#10;")[0].split("\n")
		#Get Destination Node Name
		destNodeNames=getText(ComMatrix.getElementsByTagName('Worksheet')[0].getElementsByTagName('Table')[0].getElementsByTagName('Row')[row_ele].getElementsByTagName('Cell')[3].getElementsByTagName('Data')[0].childNodes)
		#Get Destination IPs
		destIPs=getText(ComMatrix.getElementsByTagName('Worksheet')[0].getElementsByTagName('Table')[0].getElementsByTagName('Row')[row_ele].getElementsByTagName('Cell')[4].getElementsByTagName('Data')[0].childNodes)
		destIPs_lined=destIPs.split("&#10;")[0].split("\n")
		#Call to check connection
		checkConnection(sourceNodeName,srcIPs_lined,destIPs_lined,destPorts_lined,destNodeNames)

# Dunno why I did it , but I did and it's useful.
# PNP Fns , to be usd in any thing l8r on.
def getText(nodelist):
	rc = []
	for node in nodelist:
		if node.nodeType == node.TEXT_NODE:
			rc.append(node.data)
	return ''.join(rc)

def getPasswd(srcIP):
	pw=[]
	#check if file exist
	if os.path.exists("Dictpw.txt") :
		#check if json file or not
		try:
			data=json.load(open("Dictpw.txt"))
		except ValueError, error:
			pw = []
		try:
			en_pw=str(data[srcIP])
			pw=base64.b64decode(en_pw)
		except:
			pw=[]
	else:
		f = open("Dictpw.txt","w+")
		f.close()
	return pw



def saveInDict(srcIP, pw):
	encrypt_pw = base64.b64encode(pw)
	row={srcIP:encrypt_pw}
	try:
		data = json.load(open("Dictpw.txt"))
		data.update(row)
        	json.dump(data, open("Dictpw.txt", "w"))
	except ValueError, error:
		json.dump(row,open("Dictpw.txt", "w"))

def checkPW(IP, PW):
	output=""
	try:
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(IP, username='root', password=str(PW))
	except paramiko.ssh_exception.AuthenticationException:
		output="wrong"
	print("Output:"+output)
	return output

def testSrcIP(IP):
	sysType=os.uname()[0]
	pingStatement=""
	output=[]
	if sysType == "SunOS":
		pingStatement="ping "+IP+" 1"
	else:
		pingStatement="ping -w1 "+IP
	process = subprocess.Popen(pingStatement, shell=True, stdout=subprocess.PIPE)
	process.wait()
	if process.returncode == 0:
		output="true"
	return output

# Hell Caller
def checkConnection(sourceNodeName,srcIPs_lined,destIPs_lined,destPorts_lined,destNodeNames):
	for srcIP in srcIPs_lined:
		if testSrcIP(srcIP) == "true":
			count = 0
			password = getPasswd(srcIP)
			if password == []:
				password=getpass.getpass("Please enter root password for "+sourceNodeName+" (IP:"+str(srcIP)+"): ")
				while checkPW(srcIP, password) == "wrong" and count < 3:
					print("Count "+str(count))
					count+=1
					password=getpass.getpass("Invalid password, please re-enter root password: ")
			if count < 3:
				saveInDict(srcIP, password)
				srcIPtesting = sourceIPTesting(sourceNodeName,srcIP,destIPs_lined,destPorts_lined,destNodeNames,password)
				srcIPtesting.testConnectivity()
			else:
				print("Invalid Password, please check later for IP "+srcIP)
		else:
			print("Src ("+sourceNodeName+") with IP: "+str(srcIP)+" is not reachable from Central Server")

# Augh OO $#!t!!!
def main():
	path=sys.argv[1]
	parseXML(path)
	
if __name__=='__main__':
	main()
