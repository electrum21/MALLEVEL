# Mini Utility File for generating API keys (for agent authentication)

import hashlib
from constants import XOR_ENCRYPTION_KEY
from itertools import cycle

def xor_api_key(api_key): 
    return ''.join(chr(ord(c)^ord(k)) for c,k in zip(api_key, cycle(XOR_ENCRYPTION_KEY)))

def generate_api_keys(db, no_of_keys): # Generates specified number of API keys with limited information (can manually assign key)
    api_keys = db.api_keys
    try:
        api_keys.create_index([('api_key', 1)], unique=True) # to prevent duplicate api keys
    except:
        pass
    for i in range(no_of_keys):
        date_obj = dt.now()
        date_str = date_obj.strftime("%Y-%m-%d-%H-%M-%S")
        api_key = xor_api_key(str(uuid.uuid4()))
        api_keys_sample_dict = {
                "api_key": api_key,
                "web_username": None,
                "hostname": None, # will be updated once agent connects with the respective API key
                "username": None, # will be updated once agent connects with the respective API key
                "ip": None, # will be updated once agent connects with the respective API key
                "generated_on": date_str
            }
        api_keys.insert_one(api_keys_sample_dict)

if __name__ == '__main__':
    import uuid
    from datetime import datetime as dt
    from pymongo import MongoClient   
    client = MongoClient(host="localhost", port=27017, serverSelectionTimeoutMS = 2)
    db = client.mallevel       
    generate_api_keys(db, 3) # modify number of keys to be generated