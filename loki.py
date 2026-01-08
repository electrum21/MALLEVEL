# -*- coding: utf-8 -*-

"""
Loki
Simple IOC Scanner

Detection is based on three detection methods:

1. File Name IOC
   Applied to file names

2. Yara Check
   Applied to files and processes

3. Hash Check
   Compares known malicious hashes with the ones of the scanned files

Loki combines all IOCs from ReginScanner and SkeletonKeyScanner and is the
little brother of THOR our full-featured corporate APT Scanner

Florian Roth

DISCLAIMER - USE AT YOUR OWN RISK.
"""

import os
import yara         # install 'yara-python' module not the outdated 'yara' module
import platform
import lief
from sys import platform as _platform
from collections import Counter
from bisect import bisect_left

# LOKI Modules
from lib.levenshtein import LevCheck

from lib.helpers import *
from constants import *
from remote_logging import do_remote_logging
from mongodb_crud import check_if_hash_is_whitelisted

def ioc_contains(sorted_list, value):
    # returns true if sorted_list contains value
    index = bisect_left(sorted_list, value)
    return index != len(sorted_list) and sorted_list[index] == value

class Loki(object):

    # Signatures
    yara_rules = []
    filename_iocs = []
    hashes_md5 = {}
    hashes_sha1 = {}
    hashes_sha256 = {}
    false_hashes = {}
    c2_server = {}

    # File type magics
    filetype_magics = {}
    max_filetype_magics = 0

    def __init__(self, logger, remote_logger, intense_mode, os_platform, signatures):

        # Scan Mode
        self.intense_mode = intense_mode
        
        # Get application path
        self.app_path = MALLEVEL_PATH
        self.logger = logger
        self.remote_logger = remote_logger # Added: Splunk logging
        self.os_platform = os_platform
        
        # Set all the initialized signatures; signatures = [YARA Rules, Filename IOCs, MD5 Dict, MD5 List, SHA1 Dict, SHA1 List, SHA256 Dict, SHA256 List, FileType Magics, Max FileType Magics, (External) Code Signing Blocklist]
        # Previously all signatures were initialized every time a scan was executed; very inefficient, hence now they are initialized before MALLEVEL starts and are passed to the detector
        # try:
        self.yara_rules = signatures[0] 
        self.filename_iocs = signatures[1] 
        self.hashes_md5 = signatures[2]
        self.hashes_md5_list = signatures[3]
        self.hashes_sha1 = signatures[4]
        self.hashes_sha1_list = signatures[5]
        self.hashes_sha256 = signatures[6]
        self.hashes_sha256_list = signatures[7]
        self.filetype_magics = signatures[8]
        self.max_filetype_magics = signatures[9]
        self.code_signing_blocklist = signatures[10]
        # except:
        #     self.hashes_md5_list = None
        #     self.hashes_sha1_list = None
        #     self.hashes_sha256_list = None
        
        self.logger.log("NOTICE", "Init", "Starting MALLEVEL Scan VERSION: {3} SYSTEM: {0} TIME: {1} PLATFORM: {2}".format(getHostname(os_platform), self.logger.getSyslogTimestamp(), getPlatformFull(), self.logger.version))
        do_remote_logging(remote_logger, "NOTICE", ["Init", "Starting MALLEVEL Scan VERSION: {3} SYSTEM: {0} TIME: {1} PLATFORM: {2}".format(getHostname(os_platform), self.logger.getSyslogTimestamp(), getPlatformFull(), self.logger.version)])
        
        # Check if signature database is present
        sig_dir = os.path.join(self.app_path, "signature-base")
        if not os.path.exists(sig_dir) or os.listdir(sig_dir) == []:
            self.logger.log("NOTICE", "Init", "The 'signature-base' subdirectory doesn't exist or is empty. Please update the signature database before trying again.")
            do_remote_logging(remote_logger, "NOTICE", ["Init", "The 'signature-base' subdirectory doesn't exist or is empty. Please update the signature database before trying again."])
            return None

        # Levenshtein Checker
        self.LevCheck = LevCheck()

    def scan_file(self, path, original_filename, files):
        # Check if current file exists in MALLEVEL MongoDB; if it exists, just extract the report from MongoDB instead of going through entire scan process
        whitelisted = False
        try:
            with open(path, 'rb') as scan_file:
                data = scan_file.read()    
                sha256_hash = hashlib.sha256(data).hexdigest()
            for doc in files.find():
                if doc['sha256'] == sha256_hash:
                    results_summary = doc
                    results_summary['secured_file_name'] = original_filename # the same file may be submitted with different names, hence modify fetched report to match name of file submitted
                    results_summary['in_mongodb'] = True
                    self.logger.log("INFO", "FileScan", "The file %s has been found in the MALLEVEL database, hence the scan will be skipped and the report will be fetched from the database" % original_filename)
                    return results_summary
            whitelisted = check_if_hash_is_whitelisted(sha256_hash) # handle whitelisted files which may be submitted by web UI (on agent-side, whitelisted files will not be sent to server in the first place)
        except:
            pass

        results_summary = {}
        filename = path.split('\\')[-1] # for Windows Path Separator
        # filename = path.split('/')[-1] # for Linux Path Separator
        # Check if path exists
        if not os.path.exists(path):
            self.logger.log("ERROR", "FileScan", "Non-Existent File %s ...  " % filename)
            do_remote_logging(self.remote_logger, "ERROR", ["FileScan", "Non-Existent File %s ...  " % filename])
            return None

        # Startup
        self.logger.log("INFO", "FileScan", "Scanning File %s ...  " % filename)
        do_remote_logging(self.remote_logger, "INFO", ["FileScan", "Scanning File %s ...  " % filename])
        filePath = path
        reasons = []
        # Total Score
        total_score = 0

        # Get the file and path
        fpath = os.path.split(filePath)[0]
        # Clean the values for YARA matching
        # > due to errors when Unicode characters are passed to the match function as
        #   external variables
        filePathCleaned = fpath.encode('ascii', errors='replace')
        fileNameCleaned = filename.encode('ascii', errors='replace')
        extension = os.path.splitext(filePath)[1].lower()
        fileSize = os.stat(filePath).st_size

        # File Name Checks -------------------------------------------------
        for fioc in self.filename_iocs:
            match = fioc['regex'].search(filePath)
            if match:
                # Check for False Positive
                if fioc['regex_fp']:
                    match_fp = fioc['regex_fp'].search(filePath)
                    if match_fp:
                        continue
                # Create Reason
                reasons.append("File Name IOC matched PATTERN: %s SUBSCORE: %s DESC: %s" % (fioc['regex'].pattern, fioc['score'], fioc['description']))
                total_score += int(fioc['score'])

        # Levenshtein Check
        result = self.LevCheck.check(filename)
        if result:
            reasons.append("Levenshtein check - filename looks much like a well-known system file "
                            "SUBSCORE: 40 ORIGINAL: %s" % result)
            total_score += 60

        # Access check (also used for magic header detection)
        firstBytes = b""
        firstBytesString = b"-"
        hashString = ""
        try:
            with open(filePath, 'rb') as f:
                firstBytes = f.read(4)
        except Exception as e:
            self.logger.log("DEBUG", "FileScan", "Cannot open file %s (access denied)" % filePathCleaned)
            do_remote_logging(self.remote_logger, "DEBUG", ["FileScan", "Cannot open file %s (access denied)" % filePathCleaned])
        # Evaluate Type
        fileType = get_file_type(filePath, self.filetype_magics, self.max_filetype_magics, self.logger)

        do_intense_check = True

        # Set fileData to an empty value
        fileData = ""

        # Intense Check switch
        if do_intense_check:
            self.logger.log("INFO", "FileScan", "Scanning %s TYPE: %s SIZE: %s" % (fileNameCleaned, fileType, fileSize))
            do_remote_logging(self.remote_logger, "INFO", ["FileScan", "Scanning %s TYPE: %s SIZE: %s" % (fileNameCleaned, fileType, fileSize)])
        
        # Hash Check -------------------------------------------------------
        if do_intense_check:
            fileData = self.get_file_data(filePath)
            # First bytes
            firstBytesString = "%s / %s" % (fileData[:20].hex(), removeNonAsciiDrop(fileData[:20]))
            # Hash Eval
            matchType = None
            matchDesc = None
            matchHash = None
            md5 = 0
            sha1 = 0
            sha256 = 0

            md5, sha1, sha256 = generateHashes(fileData)
            md5_num=int(md5, 16)
            sha1_num=int(sha1, 16)
            sha256_num=int(sha256, 16)

            # Malware Hash
            if ioc_contains(self.hashes_md5_list, md5_num):
                matchType = "MD5"
                matchDesc = self.hashes_md5[md5_num]
                matchHash = md5
            if ioc_contains(self.hashes_sha1_list, sha1_num):
                matchType = "SHA1"
                matchDesc = self.hashes_sha1[sha1_num]
                matchHash = sha1
            if ioc_contains(self.hashes_sha256_list, sha256_num):
                matchType = "SHA256"
                matchDesc = self.hashes_sha256[sha256_num]
                matchHash = sha256

            # Hash string
            hashString = "MD5: %s SHA1: %s SHA256: %s" % ( md5, sha1, sha256 )

            if matchType:
                reasons.append("Malware Hash TYPE: %s HASH: %s SUBSCORE: 100 DESC: %s" % (
                matchType, matchHash, matchDesc))
                total_score += 100

            # Script Anomalies Check
            if extension in SCRIPT_EXTENSIONS or type in SCRIPT_TYPES:
                self.logger.log("DEBUG", "FileScan", "Performing character analysis on file %s ... " % filePath)
                do_remote_logging(self.remote_logger, "DEBUG", ["FileScan", "Performing character analysis on file %s ... " % filePath])
                message, score = self.script_stats_analysis(fileData)
                if message:
                    reasons.append("%s SCORE: %s" % (message, score))
                    total_score += score

            # Scan the read data
            try:
                for (score, rule, description, reference, matched_strings, author) in \
                        self.scan_data(fileData=fileData,
                                        fileType=fileType,
                                        fileName=fileNameCleaned,
                                        filePath=filePathCleaned,
                                        extension=extension,
                                        md5=md5  # legacy rule support
                                        ):
                    # Message
                    message = "Yara Rule MATCH: %s SUBSCORE: %s DESCRIPTION: %s REF: %s AUTHOR: %s" % \
                                (rule, score, description, reference, author)
                    # Matches
                    if matched_strings:
                        message += " MATCHES: %s" % matched_strings

                    total_score += score
                    reasons.append(message)

            except Exception as e:
                self.logger.log("ERROR", "FileScan", "Cannot YARA scan file: %s" % filePathCleaned)
                do_remote_logging(self.remote_logger, "ERROR", ["FileScan","Cannot YARA scan file: %s" % filePathCleaned])
        
            # if the file is a PE and has not been detected by any hashes or YARA rule matches,
            # then check its code signing certificate to determine whether it has been previously
            # used in malware; the blocklist is from MalwareBazaar
            if total_score == 0 and fileType == "EXE":
                message, code_sign_score = self.compare_pe_code_signing_certificates(filePath)
                if message:
                    reasons.append(message)
                    total_score += code_sign_score
                
        # Info Line -----------------------------------------------------------------------
        fileInfo = "FILE: %s SCORE: %s TYPE: %s SIZE: %s FIRST_BYTES: %s %s %s " % (
            filename, total_score, fileType, fileSize, firstBytesString, hashString, getAgeString(filePath))  # originally Loki logs file path

        # Reasons to message body
        message_body = fileInfo
        for i, r in enumerate(reasons):
            # if i < 2:
            message_body += "REASON_{0}: {1}".format(i+1, r)
            
        # Now print the total result
        if total_score >= 70:
            message_type = "DANGEROUS"
        else:
            message_type = "SAFE"
        self.logger.log(message_type, "FileScan", message_body)
        do_remote_logging(self.remote_logger, message_type, ["FileScan", message_body])
        
        #Added: Results Summary Dictionary
        results_summary["signature_detection_score"] = total_score
        results_summary["file_name"] = filename
        results_summary["original_file_name"] = original_filename
        results_summary["file_size"] = round(fileSize/1024, 2)
        results_summary["file_type"] = fileType
        results_summary["md5"] = md5
        results_summary["sha1"] = sha1
        results_summary["sha256"] = sha256
        if whitelisted:
            results_summary["verdict"] = "SAFE"
            results_summary["reasons"] = ["This file has been whitelisted"]
        else:
            results_summary["verdict"] = message_type
            results_summary["reasons"] = reasons
        results_summary["prediction"] = None
        results_summary["heuristics"] = None
        
        return results_summary

    def scan_data(self, fileData, fileType="-", fileName=b"-", filePath=b"-", extension=b"-", md5="-"):

        # Scan parameters
        #print fileType, fileName, filePath, extension, md5
        # Scan with yara
        try:
            for rules in self.yara_rules:

                # Yara Rule Match
                matches = rules.match(data=fileData,
                                      externals={
                                          'filename': fileName.decode('utf-8'),
                                          'filepath': filePath.decode('utf-8'),
                                          'extension': extension,
                                          'filetype': fileType,
                                          'md5': md5,
                                          'owner': "dummy"
                                      })

                # If matched
                if matches:
                    for match in matches:

                        score = 70
                        description = "not set"
                        reference = "-"
                        author = "-"

                        # Built-in rules have meta fields (cannot be expected from custom rules)
                        if hasattr(match, 'meta'):

                            if 'description' in match.meta:
                                description = match.meta['description']
                            if 'cluster' in match.meta:
                                description = "IceWater Cluster {0}".format(match.meta['cluster'])

                            if 'reference' in match.meta:
                                reference = match.meta['reference']
                            if 'viz_url' in match.meta:
                                reference = match.meta['viz_url']
                            if 'author' in match.meta:
                                author = match.meta['author']

                            # If a score is given
                            if 'score' in match.meta:
                                score = int(match.meta['score'])

                        # Matching strings
                        matched_strings = ""
                        if hasattr(match, 'strings'):
                            # Get matching strings
                            matched_strings = self.get_string_matches(match.strings)

                        yield score, match.rule, description, reference, matched_strings, author

        except Exception as e:
            print("Error line 537")

    def get_string_matches(self, strings):
        try:
            string_matches = []
            matching_strings = ""
            for string in strings:
                # print string
                extract = string[2]
                if not extract in string_matches:
                    string_matches.append(extract)

            string_num = 1
            for string in string_matches:
                matching_strings += " Str" + str(string_num) + ": " + removeNonAscii(string)
                string_num += 1

            # Limit string
            if len(matching_strings) > 140:
                matching_strings = matching_strings[:140] + " ... (truncated)"

            return matching_strings.lstrip(" ")
        except:
            print("Error line 560")

    def get_file_data(self, filePath):
        fileData = b''
        try:
            # Read file complete
            with open(filePath, 'rb') as f:
                fileData = f.read()
        except Exception as e:
            self.logger.log("DEBUG", "FileScan", "Cannot open file %s (access denied)" % filePath)
            do_remote_logging(self.remote_logger, "DEBUG", ["FileScan", "Cannot open file %s (access denied)" % filePath])
        finally:
            return fileData


    def script_stats_analysis(self, data):
        """
        Doing a statistical analysis for scripts like PHP, JavaScript or PowerShell to
        detect obfuscated code
        :param data:
        :return: message, score
        """
        anomal_chars = [r'^', r'{', r'}', r'"', r',', r'<', r'>', ';']
        anomal_char_stats = {}
        char_stats = {"upper": 0, "lower": 0, "numbers": 0, "symbols": 0, "spaces": 0}
        anomalies = []
        c = Counter(data)
        anomaly_score = 0

        # Check the characters
        for char in c.most_common():
            ascii_char = chr(char[0]) # FIX LOKI LOGIC ERROR (ORIGINALLY IT CHECKED IF CHAR[0] IS UPPER, BUT ALL CHAR[0 ARE DIGITS DUE TO COUNTER])
            if ascii_char in anomal_chars:
                anomal_char_stats[ascii_char] = char[1]
            if ascii_char.isupper():
                char_stats["upper"] += char[1]
            elif ascii_char.islower():
                char_stats["lower"] += char[1]
            elif ascii_char.isdigit():
                char_stats["numbers"] += char[1]
            elif ascii_char.isspace():
                char_stats["spaces"] += char[1]
            else:
                char_stats["symbols"] += char[1]
        # Totals
        char_stats["total"] = len(data)
        char_stats["alpha"] = char_stats["upper"] + char_stats["lower"]
        # Detect Anomalies
        if char_stats["alpha"] > 40 and char_stats["upper"] > (char_stats["lower"] * 0.9):
            anomalies.append("upper to lower ratio")
            anomaly_score += 20
        if char_stats["symbols"] > char_stats["alpha"]:
            anomalies.append("more symbols than alphanum chars")
            anomaly_score += 40
        for ac, count in anomal_char_stats.items():
            if (count/char_stats["alpha"]) > 0.05:
                anomalies.append("symbol count of '%s' very high" % ac)
                anomaly_score += 40
        # print(anomaly_score)
        # Generate message
        message = "Anomaly detected ANOMALIES: '{0}'".format("', '".join(anomalies))
        if anomaly_score > 0:
            return message, anomaly_score

        return "", 0

    # Besides matching files based on hashes and YARA rules, we can look into the certificate used to sign the PE and compare it to a blocklist    
    def compare_pe_code_signing_certificates(self, file_path):
        pe = lief.parse(file_path)
        signatures = pe.signatures
        serial_numbers = []
        for signature in signatures: # Loop through file code signing certificates (a file may have more than 1 certificate)
            for crt in signature.certificates:
                serial_number = crt.serial_number.hex()
                serial_numbers.append(serial_number)
        for serial_number in serial_numbers:
            if serial_number in self.code_signing_blocklist: # Check if code signing certificate serial number exists in blocklist; if yes, then PE is dangerous
                message = "This executable contains a code signing certificate (serial number %s) that was used in the malware: %s" % (serial_number, self.code_signing_blocklist[serial_number])
                return message, 100 # add 100 to total score if match is found (same score as matching MD5 / SHA1 / SHA256 hash)         
        return "", 0 # otherwise return 0
    
def is64bit():
    """
    Checks if the system has a 64bit processor architecture
    :return arch:
    """
    return platform.machine().endswith('64')
