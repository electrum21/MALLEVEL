# Accept parameters for this script to run properly
param($monitored_user_name, $ip_address, $port, $api_key)

# Set constants
$CURRENT_DIRECTORY = (Get-Location).path
$CURRENT_USERNAME = $env:UserName
$SERVICE_NAME = "MALLEVELAgentService"
$SERVICE_USER_NAME = "mallevel_agent" 
$SERVICE_USER_PASSWORD = "mallevel_agent"

# To create service user and its profile folders
$USER_PROFILE_PS_SCRIPT_PATH = $CURRENT_DIRECTORY + '\user-profile.ps1'
.$USER_PROFILE_PS_SCRIPT_PATH
&$USER_PROFILE_PS_SCRIPT_PATH | Create-NewProfile $SERVICE_USER_NAME $SERVICE_USER_PASSWORD

# Set certain constants for service user, and create quarantine directory to store quarantined files
$MALLEVEL_AGENT_HOME_DIR = 'C:\Users\' + $SERVICE_USER_NAME
$MALLEVEL_AGENT_SCRIPTS_DIR = 'C:\Users\' + $SERVICE_USER_NAME + '\Documents'
$MALLEVEL_AGENT_QUARANTINE_DIR = $MALLEVEL_AGENT_HOME_DIR + '\Documents\quarantine'
New-Item $MALLEVEL_AGENT_QUARANTINE_DIR -Type Directory

# Install Python and dependencies if endpoint does not have Python
python -V
if ( $LastExitCode -eq 9009) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $PYTHON_DOWNLOAD_PATH = 'C:\Users\' + $CURRENT_USERNAME + '\Downloads\python-3.10.0-amd64.exe'
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe" -OutFile $PYTHON_DOWNLOAD_PATH
    .$PYTHON_DOWNLOAD_PATH /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    Start-Sleep -Seconds 30
    ."C:\Program Files\Python310\Scripts\pip.exe" install requests
} else {
    python -m pip install requests
}

# Write command parameters to a configuration file
$MALLEVEL_AGENT_CFG_PATH = $MALLEVEL_AGENT_SCRIPTS_DIR + '\mallevel_agent.cfg'
$MALLEVEL_AGENT_CFG_CONTENT = "[MALLEVEL Server]`r`nIP Address = $ip_address ;IP Address of MALLEVEL Server,`r`nPort = $port                                                                    	;Port of MALLEVEL Server, e.g. 5000`r`n`r`n[MALLEVEL Agent]`r`nAPI Key = $api_key                                  ;API Key to authenticate connection to server`r`nService User = $SERVICE_USER_NAME							; Should be constant in enterprise deployment`r`nMonitored User = $monitored_user_name                                			; Monitored user may vary based on endpoint`r`nLog Directory = Documents\\Logs                    				;set a directory to store agent logs; good to keep a record of local activities. preferably the directory should be in same directory as agent scripts for easy trackability...`r`nReport Directory = Documents\\Reports"
$MALLEVEL_AGENT_CFG_CONTENT | Out-File -Encoding "UTF8" -FilePath $MALLEVEL_AGENT_CFG_PATH

# Assign service user permissions to access monitored user's folders and subfolders
$MONITORED_USER_HOME_DIR = 'C:\Users\' + $monitored_user_name
$ACL = Get-Acl $MONITORED_USER_HOME_DIR
$ACCESS_RULE = New-Object System.Security.AccessControl.FileSystemAccessRule($SERVICE_USER_NAME,"FullControl","ContainerInherit,ObjectInherit","None","Allow")
$ACL.SetAccessRule($ACCESS_RULE)
$ACL | Set-Acl $MONITORED_USER_HOME_DIR
Get-ChildItem -Path "$MONITORED_USER_HOME_DIR" -Recurse -Force | Set-Acl -aclObject $ACL

# Obtain essential paths
$NSSM_EXE_SOURCE_PATH = $CURRENT_DIRECTORY + '\nssm.exe'
$PYTHON_EXE_SOURCE_PATH = 'C:\Program Files\Python310\python.exe'
$MALLEVEL_AGENT_PY_SOURCE_PATH = $CURRENT_DIRECTORY + '\mallevel_agent.py'
$NSSM_EXE_DEST_PATH = $MALLEVEL_AGENT_SCRIPTS_DIR + '\nssm.exe'
$MALLEVEL_AGENT_PY_DEST_PATH = $MALLEVEL_AGENT_SCRIPTS_DIR + '\mallevel_agent.py'

# Copy scripts and binaries from Admin account to Service User account and install the MALLEVEL Agent Service using NSSM
Copy-Item $MALLEVEL_AGENT_PY_SOURCE_PATH -Destination $MALLEVEL_AGENT_PY_DEST_PATH
Copy-Item $NSSM_EXE_SOURCE_PATH -Destination $NSSM_EXE_DEST_PATH
&$NSSM_EXE_DEST_PATH install $SERVICE_NAME $PYTHON_EXE_SOURCE_PATH $MALLEVEL_AGENT_PY_DEST_PATH
&$NSSM_EXE_DEST_PATH set $SERVICE_NAME Description 'Service for MALLEVEL Agent to monitor files in current endpoint and send files to the MALLEVEL Server for scanning'
$object_SERVICE_USER_NAME = '.\' + $SERVICE_USER_NAME
&$NSSM_EXE_DEST_PATH set $SERVICE_NAME ObjectName $object_SERVICE_USER_NAME $SERVICE_USER_PASSWORD
&$NSSM_EXE_DEST_PATH start $SERVICE_NAME
