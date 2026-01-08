from os import makedirs, walk, listdir, remove
from os.path import join, exists, realpath, dirname
import shutil
import time
from datetime import datetime as dt
import requests
import json
import configparser
import codecs
import hashlib
import socket
import warnings
import sys
warnings.filterwarnings("ignore")

CONFIG_NAME = 'mallevel_agent.cfg' # name of MALLEVEL Agent configuration file
CONFIG_PATH = join(dirname(realpath(__file__)), CONFIG_NAME) # path of MALLEVEL Agent configuration file (should be in same directory as MALLEVEL Agent script)

config = configparser.ConfigParser(inline_comment_prefixes=';') # to disregard comments (provided as configuration guide)
config.read(CONFIG_PATH,encoding="utf-8-sig") # to comply with encoding of config file created by PS script

# Read configuration details from configuration file 
MALLEVEL_AGENT_SERVICE_USERNAME = config["MALLEVEL Agent"]["Service User"]
MALLEVEL_AGENT_HOME_DIRECTORY = "C:\\Users\\%s" % MALLEVEL_AGENT_SERVICE_USERNAME

MALLEVEL_API_KEY = config["MALLEVEL Agent"]["API Key"]
MONITORED_USER = config["MALLEVEL Agent"]["Monitored User"]

LOG_DIRECTORY = join(MALLEVEL_AGENT_HOME_DIRECTORY, config["MALLEVEL Agent"]["Log Directory"]) # directory to store agent's logs for record-keeping purposes
REPORTS_DIRECTORY = join(MALLEVEL_AGENT_HOME_DIRECTORY, config["MALLEVEL Agent"]["Report Directory"])
QUARANTINE_DIRECTORY = join(MALLEVEL_AGENT_HOME_DIRECTORY, "Documents\\Quarantine") # hardcoded quarantine path for service user named "mallevel_agent"

MALLEVEL_SERVER_IP = config["MALLEVEL Server"]["IP Address"] # IP of MALLEVEL Server
MALLEVEL_SERVER_PORT = config["MALLEVEL Server"]["Port"] # Port of MALLEVEL Server

MALLEVEL_UPLOAD_URL = "https://" + MALLEVEL_SERVER_IP + ":" + MALLEVEL_SERVER_PORT + "/api/uploadfile" # URL of MALLEVEL Server to send requests
MALLEVEL_CONFIG_URL = "https://" + MALLEVEL_SERVER_IP + ":" + MALLEVEL_SERVER_PORT + "/api/endpointconfig" # URL of MALLEVEL Server to send requests
MALLEVEL_QUARANTINE_URL = "https://" + MALLEVEL_SERVER_IP + ":" + MALLEVEL_SERVER_PORT + "/api/quarantinestatus" # URL of MALLEVEL Server to send requests

# on server, the counts are initialized as 0. hence when client first connects to server, there will be mismatch (and hence server pushes all configurations to endpoint)
client_counts = {"dcount": -1, "mcount": -1, "wcount": -1}

request_session = requests.Session()
request_session.headers.update({'Authorization': MALLEVEL_API_KEY})

# MALLEVEL Agent Logger - to log endpoint activity locally, for record-keeping purposes
class MALLEVELAgentLogger:
    def __init__(self, log_path):
        self.log_path = log_path
        
    def getSyslogTimestamp(self):
        date_obj = dt.now()
        date_str = date_obj.strftime("%Y-%m-%d %H:%M:%S")
        return date_str    
    
    def log(self, message, mes_type, module):
        try:
            # Write to file
            with codecs.open(self.log_path, "a", encoding='utf-8') as logfile:
                log_message = "%s MALLEVEL: %s: MODULE: %s MESSAGE: %s\n" % (self.getSyslogTimestamp(), mes_type.title(), module, message)
                logfile.write(log_message)
        except Exception as e:
            print("Cannot print line to log file {0}".format(self.log_path))
         
# Return list of files in a directory
def list_directory_files(monitor_directory):
    full_file_paths = []
    for monitor_path in monitor_directory: # for each path in the list of monitored paths, walk through it to discover any new files
        for dirpath, subdirs, files in walk(monitor_path):
            full_file_paths.extend(join(dirpath, x) for x in files)
    return full_file_paths

# Compare 2 lists of files
def compare_directory_files(original_list, new_list):
    differences_list = []
    for new_path in new_list:
        if new_path not in original_list:
            if calculate_sha256(new_path) not in WHITELISTED_HASHES: # Everytime there is a new file, check whether it is whitelisted. If whitelisted, do not need to send to server for scanning.
                differences_list.append(new_path) # Note if files get deleted, this will not highlight them
    return differences_list

# Responsible for uploading new files in monitored directory to MALLEVEL Server for scanning
def send_new_files(new_files, MALLEVEL_UPLOAD_URL, logger):
    files =  [('file', open(f, 'rb')) for f in new_files] # wrap all new files in list for POST request
    date_obj = dt.now()
    date_str = date_obj.strftime("%Y-%m-%d-%H-%M-%S")
    scan_report_name = "mallevel-analysis-report-%s.json" % date_str
    file_paths_dict = {}
    if len(new_files) == 1:
        new_file_name = new_files[0].split('\\')[-1]
        file_paths_dict[new_files[0]] = new_file_name # dictionary of filepath (as key) to filename; for quarantining purposes later on
        line1 = "MALLEVEL Agent has detected a new file: %s." % str(new_file_name)
        line2 = "MALLEVEL Agent has sent the file: %s to the MALLEVEL Server." % str(new_file_name)
        line3 = "MALLEVEL Scanning is in progress..."
    else:
        new_file_names = []
        for new_file in new_files:
            new_file_name = new_file.split('\\')[-1]
            new_file_names.append(new_file_name)
            file_paths_dict[new_file] = new_file_name # dictionary of filepath (as key) to filename; for quarantining purposes later on
        line1 = "MALLEVEL Agent has detected %d new files: %s." % (len(new_file_names), str(new_file_names))
        line2 = "MALLEVEL Agent has sent the files: %s to the MALLEVEL Server." % str(new_file_names) 
        line3 = "MALLEVEL Scanning is in progress..." 
    logger.log(line1, 'INFO', 'FileMonitor')
    print(line1)
    info = SELF_INFO
    info["filepaths"] = json.dumps(file_paths_dict)
    response = request_session.post(MALLEVEL_UPLOAD_URL, files = files, data = info, verify = False)
    if response.status_code == 401:
        return []
    logger.log(line2, 'INFO', 'FileMonitor')
    logger.log(line3, 'INFO', 'FileMonitor')
    print(line2 + '\n' + line3)
    scan_report_path = join(REPORTS_DIRECTORY, scan_report_name)
    scan_report_dict = response.json()
    malicious_files = scan_report_dict["statistics"]["malicious_files"]
    # malicious_files = ['eicar.com.txt', 'chrome.exe'] # hard coded malicious file names because testing on host
    with open(scan_report_path, "w") as write_file: # download the JSON response from MALLEVEL Server
        json.dump(scan_report_dict, write_file, indent=4)
    message = "MALLEVEL Scan is complete! The analysis report has been saved to %s" % (scan_report_path)
    logger.log(message, 'INFO', 'FileMonitor')    
    print(message)
    return malicious_files
   
def query_quarantine_status():
    monitored_user_quarantine_directory = join(QUARANTINE_DIRECTORY, MONITORED_USER)
    if not exists(monitored_user_quarantine_directory):
        makedirs(monitored_user_quarantine_directory)
    files_in_quarantine = listdir(monitored_user_quarantine_directory)
    info = SELF_INFO
    info["files_in_quarantine"] = json.dumps(files_in_quarantine)
    response = request_session.post(MALLEVEL_QUARANTINE_URL, data = info, verify = False)
    try:   
        files_status = response.json()
        files_to_release = files_status["release"]
        files_to_delete = files_status["delete"]
        if files_to_release != {}:
            for file_to_release, original_file_path in files_to_release.items():
                if exists(join(monitored_user_quarantine_directory, file_to_release)):
                    shutil.move(join(monitored_user_quarantine_directory, file_to_release), original_file_path)
                    line = "MALLEVEL Agent has restored a file that was previously quarantined: %s." % str(file_to_release)
                    print(line)
                    logger.log(line, 'INFO', 'Quarantine')
        if files_to_delete != {}:
            for file_to_delete, original_file_path in files_to_delete.items():
                if exists(join(monitored_user_quarantine_directory, file_to_delete)):
                    remove(join(monitored_user_quarantine_directory, file_to_delete), original_file_path)
                    line = "MALLEVEL Agent has deleted a file that was previously quarantined: %s." % str(file_to_delete)
                    print(line)
                    logger.log(line, 'INFO', 'Quarantine')
    except:
        pass
        
   
# Responsible for monitoring files and subdirectories in the specified directory, at the specified time interval
def file_monitor(monitor_directory, monitor_interval, logger):
    while True:
        query_quarantine_status() # can also be used to check server status: if request_session.exceptions.ConnectionError, that means the server is down...
        message = "MALLEVEL Agent is monitoring the files in %s every %d seconds..." % (monitor_directory, float(monitor_interval))
        logger.log(message, 'INFO', 'FileMonitor')
        print(message)
        if 'watching' not in locals(): # Check if this is the first time the function has run
            previous_file_paths_list = list_directory_files(monitor_directory)
            watching = 1 
        time.sleep(float(monitor_interval))
        new_file_paths_list = list_directory_files(monitor_directory)
        different_files = compare_directory_files(previous_file_paths_list, new_file_paths_list)
        previous_file_paths_list = new_file_paths_list
        if len(different_files) == 0: continue
        malicious_files = send_new_files(different_files, MALLEVEL_UPLOAD_URL, logger) # previously when quarantine function was nested in send_new_files function, there was permission error (possibly because of post request of files to flask server), hence call it separately, in next line
        if malicious_files != []:
            quarantine_files(malicious_files, MONITOR_DIRECTORY)
        break
    check_new_configurations(logger) # After each scan, cross-check with the server for any updated configurations
    
# Responsible for ensuring that the agent can contact the server, before file monitoring begins
# Otherwise, no point monitoring the directory if files cannot be sent to the server   
def verify_connection(logger):
    try:
        data_to_send = {**client_counts, **SELF_INFO}
        connection = request_session.post(MALLEVEL_CONFIG_URL, data = data_to_send, timeout = 3, verify = False)
        if connection.status_code == 401:
            raise Exception
        configurations = connection.json()
        message = "MALLEVEL Agent is successfully connected to the MALLEVEL server at %s:%s" % (MALLEVEL_SERVER_IP, MALLEVEL_SERVER_PORT)
        print(message)
        logger.log(message, 'INFO', 'Connect')
        return configurations
    except:
        line1 = "MALLEVEL Agent is unable to connect to the MALLEVEL server at %s:%s." % (MALLEVEL_SERVER_IP, MALLEVEL_SERVER_PORT)
        line2 = "Ensure that you are using your own API Key, and that you have configured the correct settings."
        print(line1 + "\n" + line2)
        logger.log(line1, 'ERROR', 'Connect')
        logger.log(line2, 'ERROR', 'Connect')
        sys.exit() # Exit entire program if agent cannot contact server

# Agent performs local quarantining of files found to be malicious, to the quarantine directory
def quarantine_files(file_list, monitor_directory):
    for monitored in monitor_directory: 
        for file_name in file_list:
            if exists(join(monitored, file_name)): # check whether the current malicious file exists in the current directory (since MALLEVEL supports monitoring of multiple directories)
                quarantine_path = join(QUARANTINE_DIRECTORY, MONITORED_USER)
                if not exists(quarantine_path):
                    makedirs(quarantine_path)
                shutil.move(join(monitored, file_name), join(QUARANTINE_DIRECTORY, MONITORED_USER, file_name))
                message = "MALLEVEL Agent has quarantined file: %s" % file_name 
                print(message)
                logger.log(message, 'NOTICE', 'Quarantine')
    
# Ensure that all the relevant and necessary directories exist before starting the monitor
def check_directory_exists(logger):
    directories = [REPORTS_DIRECTORY, QUARANTINE_DIRECTORY]
    for monitor_directory in MONITOR_DIRECTORY:
        if not exists(monitor_directory):
            try:
                makedirs(monitor_directory)
                message = "MALLEVEL Agent has created the directory '%s' as it did not exist previously" % monitor_directory 
                print(message)
                logger.log(message, 'INFO', 'DirCheck')
            except:
                message = "An unexpected error has occurred."
                print(message)
                logger.log(message, 'ERROR', 'DirCheck')
                return False
        else:
            message = "MALLEVEL Agent has verified the directory '%s' exists" % monitor_directory
            print(message)
            logger.log(message, 'INFO', 'DirCheck')
    try:
        for directory in directories:
            if not exists(directory):
                makedirs(directory)
                message = "MALLEVEL Agent has created the directory '%s' as it did not exist previously" % directory # if directory does not exist, automatically create it for the user in order to continue program flow
            else:
                message = "MALLEVEL Agent has verified the directory '%s' exists" % directory
            logger.log(message, 'INFO', 'DirCheck')
            print(message)
        logger.log(message, 'INFO', 'DirCheck')
        message = "MALLEVEL Agent has been successfully initialized..."
        logger.log(message, 'INFO', 'Init')
        print(message)
        return True # confirms that the necessary directories exist, and returns the path to the whitelisted directory
    except:
        message = "Please ensure that you have specified the correct paths, in the correct format"
        print(message)
        logger.log(message, 'ERROR', 'DirCheck')
        return False

# Ensure that all the configurations are valid before starting the monitor
def initialize_agent(logger):
    message = "Starting the MALLEVEL Agent..."
    print(message)
    logger.log(message, 'INFO', 'Init')

# Ensure that the logging directory exists before logging of MALLEVEL agent activities
def initialize_logger():
    date_obj = dt.now()
    log_file_name = date_obj.strftime("%Y-%m-%d_logs.txt") # since logging is not as important as compared to scanning server, save all agent logs into a daily log rather than individual agent monitoring
    if not exists(LOG_DIRECTORY):
        makedirs(LOG_DIRECTORY)
        message = "MALLEVEL Agent has created the log directory '%s' as it did not exist previously" % LOG_DIRECTORY # if user-defined directory does not exist, automatically create it for the user in order to continue program flow
    else:
        message = "MALLEVEL Agent has verified the log directory '%s' exists" % LOG_DIRECTORY
    print(message)
    log_file_path = join(LOG_DIRECTORY, log_file_name) 
    logger = MALLEVELAgentLogger(log_file_path)
    return logger


def set_configurations(configurations):    
    monitored_user_home_path = "C:\\Users\\%s" % MONITORED_USER # Assuming that administrator has already granted service user RW permissions on C:\\Users\\<monitored_user>
    dir_to_monitor = []
    try:
        monitor_directories = configurations['monitor_directory']
        if monitor_directories == []:
            dir_path = join(monitored_user_home_path, "Downloads") # if server DB does not have any directories to monitor, monitor Downloads by default
            monitor_directory = [dir_path]
        else:
            for monitor_directory in monitor_directories:
                dir_path = join(monitored_user_home_path, monitor_directory)
                if exists(dir_path):
                    dir_to_monitor.append(dir_path)
            monitor_directory = dir_to_monitor 
    except:
        monitor_directory = None # if None, means no changes to current configs
    try:    
        monitor_interval = configurations['monitor_interval']
    except:
        monitor_interval = None
    try:
        whitelisted_hashes = configurations['whitelisted_hashes']
    except:
        whitelisted_hashes = None
    return monitor_directory, monitor_interval, whitelisted_hashes

def calculate_sha256(file_path, block_size=65536):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()
    
def check_new_configurations(logger):
    configurations = verify_connection(logger)  # Check that MALLEVEL server is up so files can be successfully sent
    if configurations:
        global REPORTS_DIRECTORY
        global MONITOR_INTERVAL
        global MONITOR_DIRECTORY
        global WHITELISTED_HASHES
        monitor_directory, monitor_interval, whitelisted_hashes = set_configurations(configurations) # Set all constants using configs pushed by server to endpoint
        if monitor_directory != None: # this means server configuration has changed for monitor directory
            MONITOR_DIRECTORY = monitor_directory # hence sync configurations
            client_counts["dcount"] = configurations["dcount"] # and update dcount
            message = "Fetched new list of directories to be monitored"
            print(message)
            logger.log(message, 'INFO', 'Init')
        if monitor_interval != None:
            MONITOR_INTERVAL = monitor_interval
            client_counts["mcount"] = configurations["mcount"] # and update dcount
            message = "Fetched new time interval for monitoring of directories"
            print(message)
            logger.log(message, 'INFO', 'Init')
        if whitelisted_hashes != None:
            WHITELISTED_HASHES = whitelisted_hashes
            client_counts["wcount"] = configurations["wcount"] # and update dcount
            message = "Fetched new list of whitelisted hashes"
            print(message)
            logger.log(message, 'INFO', 'Init')
        check_directory_exists(logger)
        file_monitor(MONITOR_DIRECTORY, MONITOR_INTERVAL, logger)
    
if __name__ == '__main__':
    # try:
    #     logger = initialize_logger()
    #     initialize_agent(logger)
    #     SELF_INFO = {"username" : getlogin(), "hostname" : environ["COMPUTERNAME"]}
    #     check_new_configurations(logger) # Start monitoring files once all checks are done
    # except KeyboardInterrupt:
    #     message = "Terminating the MALLEVEL Agent..."
    #     if logger:
    #         logger.log(message, "INFO", "FileMonitor")
    #     print(message)
    # except:
    #     message = "An unexpected error has occurred..."
    #     if logger:
    #         logger.log(message, "INFO", "FileMonitor")
    #     print(message)
    logger = initialize_logger()
    initialize_agent(logger)
    SELF_INFO = {"username" : MONITORED_USER, "hostname" : socket.gethostname(), "ip" : socket.gethostbyname(socket.gethostname())} # send client details to server
    check_new_configurations(logger)
    
