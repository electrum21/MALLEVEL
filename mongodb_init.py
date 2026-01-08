# One-off operations to initialize MongoDB database (can be used to create, update, and/or delete based on requirements)
# Have to run this in order for web UI to be functioning as expected (since some views fetch data from the MongoDB database)

from api_key_generator import xor_api_key
import hashlib
from pymongo import MongoClient
import uuid

def calculate_sha256(file_path, block_size=65536):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest() 

def drop_collection(db_collection):
    db_collection.drop()
    
def initialize_all_collections_with_sample_data(db):
    
    # Initialize quarantine collection.
    quarantine = db.quarantine
    quarantine.create_index([('sha256_hash', 1), ('hostname', 1), ('username', 1)], unique=True) # to prevent duplicate quarantined file info
    quarantine_sample_dict_1 = {
        "sha256_hash": "66cd01a237ddcd758a62b9e177a8666ce6d734535d6843ec6178d6916d0ec772", 
        "file_name": "sample.exe",
        "file_status": "Quarantined",
        "client_file_path": "C:\\Users\\Jack Lee\\Downloads\\sample.exe",
        "hostname": "TEST_LAPTOP",
        "username": "Jack Lee",
        "web_username":"jack",
        "request_for_analysis": False
        }
    quarantine_sample_dict_2 = {
        "sha256_hash": "9d12357bbfb6589e54d471899fabcdefghfc695ec2fe2a2c17h8aabf651fd0fa", 
        "file_name": "whatsapp.exe",
        "file_status": "Quarantined",
        "client_file_path": "C:\\Users\\Jack Lee\\Downloads\\whatsapp.exe",
        "hostname": "TEST_LAPTOP",
        "username": "Jack Lee",
        "web_username":"jack",
        "request_for_analysis": False
        }
    quarantine.insert_one(quarantine_sample_dict_1)
    quarantine.insert_one(quarantine_sample_dict_2)
    
    # Initialize file_reports collection.
    file_reports = db.file_reports
    file_reports_sample_dict = {
            "secured_file_name": "eicar.com.txt",
            "verdict": "SAFE",
            "signature_detection_score": 40,
            "heuristics": None,
            "prediction": None,
            "file_type": "UNKNOWN",
            "file_size": 0.07,
            "md5": "44d88612fea8a8f36de82e1278abb02f",
            "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "reasons": [
                "Yara Rule MATCH: SUSP_Just_EICAR SUBSCORE: 40 DESCRIPTION: Just an EICAR test file - this is boring but users asked for it REF: http://2016.eicar.org/85-0-Download.html AUTHOR: Florian Roth MATCHES: Str1: X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            ]
        }
    file_reports.insert_one(file_reports_sample_dict)
    
    # Initialize directories collection. *** There will be different schema in this collection: one of the documents will be the monitoring interval, other documents will be the directories to monitor
    directories = db.directories
    directories_sample_dict_1 = {
            "interval": "5"
        }
    directories_sample_dict_2 = {
            "directory": "Downloads"
        }
    directories.insert_one(directories_sample_dict_1)
    directories.insert_one(directories_sample_dict_2)
    
    # Initialize whitelist collection. Consistent format of sha256_hash:time_whitelisted
    whitelist = db.whitelist
    whitelist.create_index([('sha256_hash', 1)], unique = True)
    whitelist_sample_dict = {
            "sha256_hash": "57add6cd692137b657fa6c97c80dcb717e60e0663c40a9a2c5a01cb911390d11",
            'name_whitelisted': "test_file.exe",
            "time_whitelisted": "2023-01-17-08-52-45"
        }
    whitelist.insert_one(whitelist_sample_dict)

    # Initialize users collection. Technically, it should only contain the admin user (to access restricted views, e.g. whitelist files). Allow non-admin users access to functions like manual file upload.
    users = db.users
    users.create_index([('username', 1)], unique = True) # to prevent duplicate usernames
    # Add sample admin user
    users_sample_dict_1 = {
            "username": "admin",
            "password": hashlib.sha256("admin".encode("UTF8")).hexdigest(), # recommended to change password immediately
            "is_admin": True
        }
    users_sample_dict_2 = {
            "username": "user",
            "password": hashlib.sha256("user".encode("UTF8")).hexdigest(), # recommended to change password immediately
            "is_admin": False
        }
    users_sample_dict_3 = {
            "username": "jack",
            "password": hashlib.sha256("p@ssw0rd".encode("UTF8")).hexdigest(), # recommended to change password immediately
            "is_admin": False
        }
    
    users.insert_one(users_sample_dict_1)
    users.insert_one(users_sample_dict_2)
    users.insert_one(users_sample_dict_3)
    
    api_keys = db.api_keys
    api_keys.create_index([('api_key', 1)], unique = True) # to prevent duplicate usernames
    api_keys_sample_dict = {
            "api_key": xor_api_key(str(uuid.uuid4())),
            "web_username": "user",
            "hostname": None, # will be updated once agent connects with the respective API key
            "username": None, # will be updated once agent connects with the respective API key - endpoint username, not web UI account username
            "ip": None, # will be updated once agent connects with the respective API key
            "generated_on": "2023-01-20-08-52-45"
        }
    api_keys.insert_one(api_keys_sample_dict)
    # Initialize api keys collection. An agent would require an API key to be connected successfully to the server (and hence constantly monitored)


if __name__ == '__main__':
    # client = MongoClient(host="localhost", port=27017, serverSelectionTimeoutMS = 2)
    # db = client.mallevel
    # quarantine = db.quarantine
    # quarantine_sample_dict_1 = {
    #     "sha256_hash": "66cd01a237ddcd758a62b9e177a8666ce6d734535d6843ec6178d6916d0ec772", 
    #     "file_name": "sample.exe",
    #     "file_status": "Quarantined",
    #     "client_file_path": "C:\\Users\\Jack Lee\\Downloads\\sample.exe",
    #     "hostname": "TEST_LAPTOP",
    #     "username": "Jack Lee",
    #     "web_username":"jack",
    #     "request_for_analysis": False
    #     }
    # quarantine_sample_dict_2 = {
    #     "sha256_hash": "9d12357bbfb6589e54d471899fabcdefghfc695ec2fe2a2c17h8aabf651fd0fa", 
    #     "file_name": "whatsapp.exe",
    #     "file_status": "Quarantined",
    #     "client_file_path": "C:\\Users\\Jack Lee\\Downloads\\whatsapp.exe",
    #     "hostname": "TEST_LAPTOP",
    #     "username": "Jack Lee",
    #     "web_username":"jack",
    #     "request_for_analysis": False
    #     }
    # quarantine.insert_one(quarantine_sample_dict_1)
    # quarantine.insert_one(quarantine_sample_dict_2)
    initialize_all_collections_with_sample_data(db)
