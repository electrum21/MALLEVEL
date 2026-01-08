# Retrieves IOCs from Open Threat Exchange
# Create an account and select your feeds
# https://otx.alienvault.com

from datetime import datetime
from OTXv2 import OTXv2
from datetime import timedelta
import os
from constants import IOCS_DIR_PATH, OTX_API_KEY
from remote_logging import do_remote_logging
import codecs

# Hashes that are often included in pulses but are false positives (pre-defined)
HASH_WHITELIST = ['e617348b8947f28e2a280dd93c75a6ad',
                  '125da188e26bd119ce8cad7eeb1fc2dfa147ad47',
                  '06f7826c2862d184a49e3672c0aa6097b11e7771a4bf613ec37941236c1a8e20',
                  'd378bffb70923139d6a4f546864aa61c',
                  '8094af5ee310714caebccaeee7769ffb08048503ba478b879edfef5f1a24fefe',
                  '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
                  'b6f9aa44c5f0565b5deb761b1926e9b6',
                  # Empty file
                  'd41d8cd98f00b204e9800998ecf8427e',
                  'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                  # One byte line break file (Unix) 0x0a
                  '68b329da9893e34099c7d8ad5cb9c940',
                  'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc',
                  '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
                  # One byte line break file (Windows) 0x0d0a
                  '81051bcc2cf1bedf378224b0a93e2877',
                  'ba8ab5a0280b953aa97435ff8946cbcbb2755a27',
                  '7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6',
                  ]

OTX_HASH_FILE_NAME = "otx-hash-updated-iocs.txt"
OTX_URL_FILE_NAME = "otx-url-updated-iocs.txt"
OTX_HASH_FILE_PATH = os.path.join(IOCS_DIR_PATH, OTX_HASH_FILE_NAME) 
OTX_URL_FILE_PATH = os.path.join(IOCS_DIR_PATH, OTX_URL_FILE_NAME) 

class WhiteListedIOC(Exception): pass

class OTXReceiver():
    # IOC Strings
    hash_iocs = ""
    url_iocs = ""
    
    # Output format
    separator = ";" # Conform to AV IOC parsing format

    def __init__(self, logger, remote_logger, api_key):
        self.otx = OTXv2(api_key)
        self.logger = logger
        self.remote_logger = remote_logger
        
    def get_iocs(self):
        # Before the regular updates, signature files were initialized with events from 1 Nov 2022...
        try:
            mtime = os.path.getmtime(OTX_URL_FILE_PATH) # Checks last modified time of OTX URL IOC file; assumes that this was the last time the file was updated; hence will only append new events after the modified time
        except:
            mtime = (datetime.now() - timedelta(days=1)).isoformat()
        last_modified_date = datetime.fromtimestamp(mtime)
        mtime = (last_modified_date).isoformat() # Conform to OTX API time format
        # days_to_load = 80 # Getting all events would be very time-consuming, hence just pick IOCs from 1 Nov 2022 as a start
        # mtime = (datetime.now() - timedelta(days=days_to_load)).isoformat() # Conform to OTX API time format
        self.events = self.otx.getall(modified_since=mtime)
        try:
            self.logger.log("INFO", "External-Upgrader", "Downloading IOCs from OTX from https://otx.alienvault.com")
            do_remote_logging(self.remote_logger, "INFO", ["External-Upgrader", "Downloading IOCs from OTX from https://otx.alienvault.com"])        
        except:
            pass
        self.events = self.otx.getall(modified_since=mtime) # Gets latest events (based on modified_since) from all subscribed feeds (based on user's subscriptions)

    # Loki's signature database included OTX Hashes, but their copy of OTX hashes have not been updated for a long period. Hence using this script, we can update the latest OTX hashes and URL IOCs.
    def write_iocs(self):
        for event in self.events:
            try:
                for indicator in event["indicators"]:
                    try:
                        # Description
                        description = event["name"]
                        # Hash IOCs
                        if indicator["type"] in ('FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256'):
                            # Whitelisting
                            if indicator["indicator"].lower() in HASH_WHITELIST:
                                raise WhiteListedIOC
                            hash = indicator["indicator"]
                            self.hash_iocs += "{0}{3}{1} {2}\n".format(hash, description, " / ".join(event["references"])[:80], self.separator)

                        # URL / Domain IOCs
                        if indicator["type"] in ('IPv4', 'domain', 'hostname', 'URL'):
                            self.url_iocs += "{0}{3}{1} {2}\n".format(indicator["indicator"], description, " / ".join(event["references"])[:80], self.separator)
                    except WhiteListedIOC as e:
                        pass
            except Exception as e:
                print(e)

        # Write to files
        with codecs.open(OTX_HASH_FILE_PATH, 'a', encoding='utf-8') as hash_fh:
            hash_fh.write(self.hash_iocs)
            if self.hash_iocs == "":
                try:
                    self.logger.log("INFO", "External-Upgrader", "No new hash IOCs were fetched from OTX.")
                    do_remote_logging(self.remote_logger, "INFO", ["External-Upgrader", "No new hash IOCs were fetched from OTX."])        
                except:
                    pass
            else:
                try:
                    self.logger.log("INFO", "External-Upgrader", "{0} new hash IOCs written to {1}".format(self.hash_iocs.count('\n'), OTX_HASH_FILE_NAME))
                    do_remote_logging(self.remote_logger, "INFO", ["External-Upgrader", "{0} new hash IOCs written to {1}".format(self.hash_iocs.count('\n'), OTX_HASH_FILE_NAME)])        
                except:
                    pass
        with codecs.open(OTX_URL_FILE_PATH, 'a', encoding='utf-8') as url_fh:
            url_fh.write(self.url_iocs)
            if self.url_iocs == "":
                try:
                    self.logger.log("INFO", "External-Upgrader", "No new URL IOCs were fetched from OTX.")
                    do_remote_logging(self.remote_logger, "INFO", ["External-Upgrader", "No new URL IOCs were fetched from OTX."])        
                except:
                        pass
            else:
                try:
                    self.logger.log("INFO", "External-Upgrader", "{0} new URL IOCs written to {1}".format(self.url_iocs.count('\n'), OTX_URL_FILE_NAME))
                    do_remote_logging(self.remote_logger, "INFO", ["External-Upgrader", "{0} new URL IOCs written to {1}".format(self.url_iocs.count('\n'), OTX_URL_FILE_NAME)])        
                except:
                    pass

if __name__ == '__main__':
    # Create a receiver
    otx_receiver = OTXReceiver(None, None, OTX_API_KEY)
    # Retrieve the events and store the IOCs
    otx_receiver.get_iocs()
    # Write IOC files
    otx_receiver.write_iocs()