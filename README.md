# Connectivity-checker using Python
Check connectivity with between multiple servers(linux and solaris only)

Steps:
  1) Create excel sheet with source, destination servers and ports need to be tested (as in excel sheet labMan) and save the sheet as an XML file.
  2) Put the script and the XML file either in a source server or a centeral server has access to all the needed sources (it should have python installed in it)
  3) Run the script with its argument the XML file.
    ex: python <script_name> <file_name>
  4) As it will require connection to remote source servers, script will ask for root password to login. 
            For new servers, it will save the password encrypted. 
            For already saved source servers, it will not ask for it.
            For already saved source server but password is changed, it will ask then update the password when it successful to login.
  5) Output should be like below printed on terminal.
    
    Src Source_Server#1 with IP: IP#1 is not reachable from Central Server
    Src Source_Server#1 with IP: IP#2 is not reachable from Central Server
    Source_Server#2		IP#1     Destination_Server#1		IP#1      Pingable        Port#1 Failed ([Errno 111] Connection refused )
    Source_Server#2		IP#1     Destination_Server#2		IP#2      Pingable        Port#1 Failed (timed out )
    Source_Server#2		IP#1     Destination_Server#3		IP#3      Pingable        Port#1 Success.
