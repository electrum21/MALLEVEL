import pymongo
from constants import MONGODB_HOST, MONGODB_PORT
from datetime import datetime as dt
from user import UserAccount
import hashlib
import uuid
from api_key_generator import xor_api_key

CLIENT = pymongo.MongoClient(host = MONGODB_HOST, port = MONGODB_PORT, serverSelectionTimeoutMS = 2) # Set timeout to small value to reduce overall process duration (default is 30)
DB = CLIENT.mallevel # intialize database name as "mallevel"

# Initialize various configurations
db_files = DB.file_reports
db_whitelist = DB.whitelist
db_directories = DB.directories
db_quarantine = DB.quarantine
db_users = DB.users
db_api_keys = DB.api_keys

# FETCH INFORMATION FROM DATABASE TO CREATE DASHBOARD FOR VISUALIZATION
def fetch_mongodb_dashboard():
    # try:
    unique_files_scanned = 0
    unique_files_ml = 0
    file_verdicts = {"SAFE":0, "DANGEROUS":0}
    file_types = {}
    for doc in db_files.find():
        unique_files_scanned += 1
        if doc["prediction"]!=None:
            unique_files_ml += 1
        if doc["verdict"] == "SAFE":
            file_verdicts["SAFE"] += 1
        else:
            file_verdicts["DANGEROUS"] += 1
        if doc["file_type"] not in file_types.keys():
            file_types[doc["file_type"]] = 1
        else:
            file_types[doc["file_type"]] += 1
    return unique_files_scanned, unique_files_ml, file_verdicts, file_types
    # except:
        # return None, None, None, None, None

def get_whitelist_hashes_mongodb():
    try:
        whitelist_hashes = []
        for doc in db_whitelist.find():
            whitelist_hashes.append(doc['sha256_hash'])
        return whitelist_hashes
    except:
        return []

def check_if_hash_is_whitelisted(hash):
    hash_exists = False
    if db_whitelist.find_one({"sha256_hash": hash}):
        hash_exists = True
    return hash_exists

def check_whitelisted_hash_in_reports(hash):
    try: # Update status of existing files in database if it becomes whitelisted
        db_filter = {"sha256": hash}
        file_new_status = {"$set": {"reasons": ['This file has been whitelisted'], "verdict": "SAFE"}}
        db_files.update_one(db_filter, file_new_status)
    except:
        pass

# ADD LIST OF WHITELIST HASHES TO DATABASE    
def add_whitelist_hashes_mongodb(whitelist_files_dict):
    try:
        new_hashes = []
        existed_hashes = []
        for hash in whitelist_files_dict:
            hash_exists = False
            if db_whitelist.find_one({"sha256_hash": hash}):
                hash_exists = True
                existed_hashes.append(hash)
            if hash_exists == False:
                date_obj = dt.now()
                date_str = date_obj.strftime("%Y-%m-%d-%H-%M-%S")
                dictionary = {'sha256_hash': hash, 'name_whitelisted': whitelist_files_dict[hash], 'time_whitelisted': date_str}
                db_whitelist.insert_one(dictionary)
                check_whitelisted_hash_in_reports(hash) # if whitelisted file already exists in file_reports, update status to "SAFE" and reasons to "This file has been whitelisted"
                new_hashes.append(hash)
        return new_hashes, existed_hashes
    except:
        return None, None

# GET LIST OF WHITELISTED FILES (10 MOST RECENT WHITELISTED FILES) FOR OVERVIEW   
def get_whitelisted_files_mongodb():
    # try:
    whitelist_files_dict = {}
    recent_whitelisted_files = db_whitelist.find().sort([('time_whitelisted', -1)]).limit(10)
    for doc in recent_whitelisted_files:
        whitelist_files_dict[doc["sha256_hash"]] = {"filename": doc["name_whitelisted"], "time":doc["time_whitelisted"]}
    return whitelist_files_dict
    # except:
    #     return None

# REMOVE DIRECTORY TO BE MONITORED FROM DATABASE   
def delete_whitelist_hash_mongodb(hash):
    try:
        whitelist_record = db_whitelist.find_one({"sha256_hash": hash})
        if whitelist_record != None:
            db_whitelist.delete_one(whitelist_record)
        return True
    except:
        return False

# FETCH LIST OF DIRECTORIES MONITORED FROM DATABASE    
def get_directory_mongodb():
    try:
        directories = []
        for doc in db_directories.find():
            if "directory" in doc:
                directories.append(doc["directory"])
        return directories
    except:
        return [] 

# ADD DIRECTORY TO BE MONITORED TO DATABASE    
def add_directory_mongodb(directory):
    try:
        directory_exists = False
        for doc in db_directories.find():
            try:
                if doc['directory'] == directory:
                    directory_exists = True
            except:
                pass
        if directory_exists == False:
            doc_to_add = {"directory": directory}
            db_directories.insert_one(doc_to_add)
            return True
        return False
    except:
        return False

# REMOVE DIRECTORY TO BE MONITORED FROM DATABASE   
def delete_directory_mongodb(directory):
    try:
        directory_record = db_directories.find_one({"directory": directory})
        if directory_record != None:
            db_directories.delete_one(directory_record)
        return True   
    except:
        return False

# FETCH LIST OF QUARANTINED FILES FOR SPECIFIED USER (FOR USER SELF VIEW)
def get_user_quarantine_mongodb(web_username):
    try:
        quarantined_files = []
        for quarantined_file in db_quarantine.find():
            if quarantined_file["web_username"] == web_username:
                sha256_hash = quarantined_file["sha256_hash"]
                file_name = quarantined_file["file_name"]
                file_status = quarantined_file["file_status"]
                request_for_analysis = quarantined_file["request_for_analysis"]
                quarantined_file_info = {"sha256_hash": sha256_hash, "file_name": file_name, "file_status": file_status, "request_for_analysis": request_for_analysis}
                quarantined_files.append(quarantined_file_info)
        return quarantined_files
    except:
        return None

# FETCH LIST OF FILES TO RELEASE AND DELETE FOR SPECIFIED USER
def get_user_files_to_release_and_delete_mongodb(hostname, username, quarantined_file_names):
    try:
        files_to_release = {}
        files_to_delete = {}
        files_status = {"release": {}, "delete": {}}
        for quarantined_file in db_quarantine.find():
            if quarantined_file["username"] == username and quarantined_file["hostname"] == hostname and quarantined_file["file_name"] in quarantined_file_names:
                if quarantined_file["file_status"] == "Released": 
                    files_to_release[quarantined_file["file_name"]] = quarantined_file["client_file_path"]
                elif quarantined_file["file_status"] == "Blacklisted":
                    files_to_delete[quarantined_file["file_name"]] = quarantined_file["client_file_path"]
        files_status["release"] = files_to_release
        files_status["delete"] = files_to_delete    
    except:
        pass
    finally:
        return files_status

def add_quarantine_mongodb(sha256_hash, file_name, client_filepath, client_hostname, client_username):
    try:
        api_key_record = db_api_keys.find_one({"hostname": client_hostname, "username": client_username})
        web_username = api_key_record["web_username"]
        quarantine_file_dict = {
            "sha256_hash": sha256_hash, 
            "file_name": file_name,
            "file_status": "Quarantined",
            "client_file_path": client_filepath,
            "hostname": client_hostname,
            "username": client_username,
            "web_username": web_username,
            "request_for_analysis": False
            }
        db_quarantine.insert_one(quarantine_file_dict)
    except:
        pass
    
# FETCH LIST OF ALL QUARANTINED FILES FROM DATABASE (FOR ADMIN VIEW)
def get_quarantine_mongodb():
    try:
        quarantined_files = []
        for quarantined_file_record in db_quarantine.find():
            sha256_hash = quarantined_file_record["sha256_hash"]
            file_name = quarantined_file_record["file_name"]
            file_status = quarantined_file_record["file_status"]
            hostname = quarantined_file_record["hostname"]
            username = quarantined_file_record["username"]
            request_for_analysis = quarantined_file_record["request_for_analysis"]
            quarantined_file_info = {"sha256_hash": sha256_hash, "file_name": file_name, "file_status": file_status, "hostname": hostname, "username": username, "request_for_analysis": request_for_analysis}
            quarantined_files.append(quarantined_file_info)
        return quarantined_files
    except:
        return {}

# CHANGE QUARANTINE STATUS OF SPECIFIED FILE IN DATABASE    
def change_quarantine_status_mongodb(sha256_hash, hostname, username, file_status):
    try:
        db_filter = {"sha256_hash": sha256_hash, "hostname": hostname, "username": username} # Take into consideration hostname and username (since same files on different endpoints can be quarantined)
        file_new_status = {"$set": {"file_status": file_status}}
        db_quarantine.update_one(db_filter, file_new_status)
        if file_status == "Released": # if file is released, means administrator has investigated file and proved it to be safe; hence it can be subsequently whitelisted
            try:
                file_name = db_quarantine.find_one(db_filter)["file_name"]
                date_obj = dt.now()
                date_str = date_obj.strftime("%Y-%m-%d-%H-%M-%S")
                dictionary = {'sha256_hash': sha256_hash, 'name_whitelisted': file_name, 'time_whitelisted': date_str}
                db_whitelist.insert_one(dictionary)
            except:
                pass
        return True
    except:
        return False

# CHANGE REQUEST_FOR_ANALYSIS FOR QUARANTINED FILE (DEFAULT IS FALSE)   
def request_file_analysis_mongodb(sha256_hash, web_username):
    try:
        db_filter = {"sha256_hash": sha256_hash, "web_username": web_username} # Take into consideration hostname and username (since same files on different endpoints can be quarantined)
        file_new_status = {"$set": {"request_for_analysis": True}}
        db_quarantine.update_one(db_filter, file_new_status)
        return True
    except:
        return False
    
# FETCH TIME INTERVAL AT WHICH DIRECTORIES ARE BEING MONITORED FROM DATABASE
def get_monitor_interval_mongodb():
    try:
        for doc in db_directories.find():
            if "interval" in doc:
                return doc["interval"]
    except:
        return 60 # default monitor interval would be 60 seconds

# CHANGE TIME INTERVAL AT WHICH DIRECTORIES ARE BEING MONITORED IN DATABASE
def change_monitor_interval_mongodb(old_interval, new_interval):
    # try:
    for doc in db_directories.find():
        if "interval" in doc:
            id = doc["_id"]
    db_filter = {"_id": id}
    file_new_status = {"$set": {"interval": new_interval}}
    db_directories.update_one(db_filter, file_new_status)
    #     return True
    # except:
    #     return False
 
# Gives admin control; ability to create new users (with default passwords) for web UI
def create_user_mongodb(username):
    try:
        # Ensure username is not taken
        user_record = db_users.find_one({"username": username})
        if user_record == None:
            db_users.insert_one({"username": username, "password": hashlib.sha256("p@ssw0rd".encode("UTF8")).hexdigest(), "is_admin": False})
            generate_api_key_mongodb(web_username = username)
            return True
        else:
            return False
    except:
        return None
 
# For Flask Login user_loader callback; return the user object. Will also cross-reference api_keys collection
def get_user_mongodb(username):
    try:
        user_record = db_users.find_one({"username": username})
        if user_record == None:
            return None
        else:
            username = user_record["username"]
            user =  UserAccount(username)
            
            # Check if user has admin role in MongoDB; if yes, assign admin power to user object. By default, users are not admins.
            if user_record["is_admin"] == True: 
                user.add_admin_power()
                
            # Check if user has an existing API key; if yes, fetch relevant information about the key.    
            user_api_key_record = db_api_keys.find_one({"web_username": username})
            if user_api_key_record != None:
                encrypted_api_key = user_api_key_record["api_key"]
                # Decrypt API key for display to user
                api_key = xor_api_key(encrypted_api_key)
                user_api_key_info = { # Just extract some important information about API key for display in web interface
                    "api_key": api_key,
                    "generated_on": user_api_key_record["generated_on"],
                    "endpoint_username": user_api_key_record["username"] 
                }
                user.add_api_key_info(user_api_key_info)
            return user
    except:
        return None

def get_all_user_details_mongodb():
    users_info = {}
    for user_record in db_users.find():
        username = user_record["username"]
        user_api_key_record = db_api_keys.find_one({"web_username": username})
        if user_record["is_admin"] == True: # do not include admins in the users display
            continue
        if user_api_key_record == None:
           user_api_key_info = {"api_key": None, "hostname": None, "username": None }
        else:
            api_key = xor_api_key(user_api_key_record["api_key"])
            user_api_key_info = {"api_key": api_key, "hostname": user_api_key_record["hostname"], "username": user_api_key_record["username"] }
        users_info[username] = user_api_key_info
    return users_info
        
def delete_user_mongodb(username):
    try:
        user_record = db_users.find_one({"username": username})
        if user_record != None:
            db_users.delete_one(user_record)
            return True
    except:
        return False
        
# Validate entered credentials on login page    
def validate_user_mongodb(username, password):
    try:
        user_record = db_users.find_one({"username": username, "password": hashlib.sha256(password.encode("UTF8")).hexdigest()})
        if user_record == None:
            return None
        else:
            username = user_record["username"]
            user = get_user_mongodb(username)
            return user 
    except:
        return None 
    
# Update user's password 
def update_password_mongodb(username, password):
    try:
        db_filter = {"username": username}
        user_new_password = {"$set": {"password": hashlib.sha256(password.encode("UTF8")).hexdigest()}}
        db_users.update_one(db_filter, user_new_password)
        return True
    except:
        return None     

# For logged in users to generate an API key (will be linked to their username)
def generate_api_key_mongodb(web_username):
    date_obj = dt.now()
    date_str = date_obj.strftime("%Y-%m-%d-%H-%M-%S")
    api_key = str(uuid.uuid4()) # Raw API Key
    
    # Encrypt the API key for storage in database
    encrypted_api_key = xor_api_key(api_key)
    
    # Encrypt API Key so actual key will not be revealed in database
    api_keys_sample_dict = {
            "api_key": encrypted_api_key,
            "web_username": web_username,
            "hostname": None, # will be updated once agent connects with the respective API key
            "username": None, # will be updated once agent connects with the respective API key
            "ip": None, # will be updated once agent connects with the respective API key
            "generated_on": date_str
        }
    try:
        # Check if current user has an existing API key
        existing_api_key_record = db_api_keys.find_one({"web_username": web_username})
        if existing_api_key_record != None:
            existing_api_key_generated_on = existing_api_key_record["generated_on"]
            date_list = existing_api_key_generated_on.split('-')
            year, month, day, hour, min, sec = int(date_list[0]), int(date_list[1]), int(date_list[2]), int(date_list[3]), int(date_list[4]), int(date_list[5])
            date_now = dt.now()
            generated_date = dt(year, month, day, hour, min, sec)
            day_difference = (date_now - generated_date).days
            if day_difference > 0: # Only allow user to generate new API key once a day; hence if day difference is 0, return None
                db_api_keys.delete_one(existing_api_key_record)
            else:
                return False    
        try:
            db_api_keys.insert_one(api_keys_sample_dict)
        except pymongo.errors.DuplicateKeyError: # in the event the random API key already exists in the database, regenerate an API key automatically
            added = False
            while added == False: # loop generation and insertion of API keys until the API key selected has not existed previously in the database
                api_key = str(uuid.uuid4())
                encrypted_api_key = xor_api_key(api_key)
                api_keys_sample_dict["api_key"] = encrypted_api_key
                try:
                    db_api_keys.insert_one(api_keys_sample_dict)
                    added = True
                except:
                    pass
        return True
    except:
        return None
    
# To validate API key
def check_api_key_mongodb(api_key, hostname, username): # ip may change frequently so not taken into consideration 
    try:
        encrypted_api_key = xor_api_key(api_key)
        api_key_record = db_api_keys.find_one({"api_key": encrypted_api_key})
        if api_key_record != None:
            if api_key_record["hostname"] == None: # if hostname not filled, need to fill it up along with other details i.e. username, IP
                return "Needs Update"
            elif hostname != None and username != None and api_key_record["hostname"] != hostname and api_key_record["username"] != username: # if API key exists but different user/host is accessing it, do not allow access
                return None
            return "Valid" # otherwise if information is filled, return valid status
        return None
    except:
        return None
    
# To update information about a particular API key (i.e. which host is used, which username (computer username, not web username), which ip address)    
def update_api_key_details_mongodb(api_key, hostname, username, ip): # Updates hostname and username when agent is first connected to the server
    try:
        encrypted_api_key = xor_api_key(api_key)
        db_filter = {"api_key": encrypted_api_key}
        api_key_new_details = {"$set": {"hostname": hostname, "username": username, "ip": ip}}
        db_api_keys.update_one(db_filter, api_key_new_details)
        return True
    except:
        return None

# To invalidate an API key
def delete_api_key_mongodb(api_key):
    try:
        encrypted_api_key = xor_api_key(api_key)
        api_key_record = db_api_keys.find_one({"api_key": encrypted_api_key})
        if api_key_record != None:
            db_api_keys.delete_one(api_key_record)
            return True
    except:
        return False

if __name__ == "__main__":
    db_whitelist = DB.whitelist