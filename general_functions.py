from sys import platform as _platform
from constants import *
import os
import time
import stat
import pefile
from splunk_logger import SplunkLogger
import shutil
from pymongo import MongoClient
from loki_objects import LokiLogger
from datetime import datetime as dt
import re
from lib.helpers import *
import mdml
# import pdfml
# import officeml
import re
import os
from pyunpack import Archive
from pymisp import PyMISP
import pandas as pd
from remote_logging import do_remote_logging
from heuristics import pe_heuristics_detection
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# PLATFORM CHECKER USED FOR LOKI LOGS
def platform_checker():
    """Function to check current platform, used for Loki logs"""
    # Win32 Imports
    if _platform == "win32":
        try:
            import wmi
            import win32api
            from win32com.shell import shell
        except Exception as e:
            platform = "linux"  # crazy guess
    # Platform
    platform = ""
    if _platform == "linux" or _platform == "linux2":
        platform = "linux"
    elif _platform == "darwin":
        platform = "macos"
    elif _platform == "win32":
        platform = "windows"
    return platform

# HOSTNAME CHECKER USED FOR LOKI LOGS
def hostname_checker(platform):
    if platform == "windows":
        t_hostname = os.environ['COMPUTERNAME']
    else:
        t_hostname = os.uname()[1]
    return t_hostname

# ADDED: RETRIEVE INFORMATION ABOUT SIGNATURE FILES STORED IN LOKI SIGNATURE-BASE DIRECTORY
def get_signatures_info(signatures_path):
    """Function to retrieve information about signature files stored within Loki's signature-base directory"""
    signatures_file_list = []
    signatures_file_info = {}
    for dirpath, subdirs, files in os.walk(signatures_path):
        signatures_file_list.extend(os.path.join(dirpath, x) for x in files)
    for signatures_file in signatures_file_list:
        signatures_file_name = signatures_file.split('\\')[-1] # for Windows Path Separator
        # signatures_file_name = signatures_file.split('/')[-1] # for Linux Path Separator
        signatures_file_size = round(os.path.getsize(signatures_file)/1000, 2)
        signatures_file_modified = time.ctime(os.stat(signatures_file)[stat.ST_MTIME]) 
        signatures_file_info[signatures_file_name] = {"path": signatures_file, "size": signatures_file_size, "modified": signatures_file_modified}
    return signatures_file_info

# ADDED: FILTER OUT FILES THAT ARE NOT ACCEPTED
def allowed_file(filename):
    """Function to filter out files of unaccepted extensions (simple-checking... later on in the scan, there will be checking of file types based on magics...)"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ADDED: ENSURE THAT ALL FILES HAVE UNIQUE NAMES AFTER SUBMISSION (E.G. NON_EICAR.txt AND NON EICAR.txt)
def check_filename(new_filename, original_file, upload_files):
    """Ensure all files are stored with unique names for each scan"""
    if upload_files!=None:
        if len(upload_files) == 1:
            pass
        else:
            upload_files.remove(original_file)
            for other_upload in upload_files:
                if other_upload.filename == new_filename:
                    new_filename += "_2"
    return new_filename

# ADDED: PRODUCE FINAL ANALYSIS REPORT WITH STATISTICS AND SCAN RESULTS
def generate_analysis_report(analysis_results, analysis_stats, files, username, hostname):
    """To produce the final analysis report, including overall statistics and individual scan results"""
    analysis_report = {}
    analysis_report["statistics"] = {}
    analysis_report["statistics"]["start_time"] = analysis_stats[0]
    analysis_report["statistics"]["end_time"] = analysis_stats[1]
    analysis_report["statistics"]["file_count"] = len(analysis_results)
    analysis_results_values = list(analysis_results.values())
    analysis_report["files"] = {}
    for i in range(len(analysis_results_values)):
        capabilities = None
        contains = None
        try: # accommodate post-processed reports from MongoDB
            key = analysis_results_values[i]["secured_file_name"]
            analysis_report["files"][key] = {}
            analysis_report["files"][key]["secured_file_name"] = analysis_results_values[i]["secured_file_name"]
        except:
            key = analysis_results_values[i]["file_name"]
            analysis_report["files"][key] = {}
            analysis_report["files"][key]["secured_file_name"] = analysis_results_values[i]["file_name"]
        try:
            contains = analysis_results_values[i]["contains"] # only available for ZIP files
        except:
            pass
        heuristics = analysis_results_values[i]["heuristics"]
        if heuristics != None:
            analysis_report["files"][key]["verdict"] = heuristics 
        else:
            analysis_report["files"][key]["verdict"] = analysis_results_values[i]["verdict"]
        prediction = analysis_results_values[i]["prediction"] # prediction is either SAFE or DANGEROUS
        if prediction != None:
            analysis_report["files"][key]["verdict"] = prediction # if prediction is not None, then final verdict would be the prediction result
        else:
            analysis_report["files"][key]["verdict"] = analysis_results_values[i]["verdict"]
        analysis_report["files"][key]["signature_detection_score"] = analysis_results_values[i]["signature_detection_score"]
        analysis_report["files"][key]["heuristics"] = heuristics
        analysis_report["files"][key]["prediction"] = prediction
        analysis_report["files"][key]["file_type"] = analysis_results_values[i]["file_type"]
        analysis_report["files"][key]["file_size"] = analysis_results_values[i]["file_size"]
        analysis_report["files"][key]["md5"] = analysis_results_values[i]["md5"]
        analysis_report["files"][key]["sha1"] = analysis_results_values[i]["sha1"]
        analysis_report["files"][key]["sha256"] = analysis_results_values[i]["sha256"]
        analysis_report["files"][key]["reasons"] = analysis_results_values[i]["reasons"]
        if capabilities:
            analysis_report["files"][key]["capabilities"] = capabilities
        # if "file_imports" in analysis_results_values[i]: # uncomment if want more verbose output
        #     analysis_report["files"][key]["file_imports"] = analysis_results_values[i]["file_imports"]    
        if contains:
            analysis_report["files"][key]["contains"] = contains
        db_file = analysis_report["files"][key].copy()
        db_file["hostname"] = hostname
        db_file["username"] = username
        db_match_count = 0
        try:
            for doc in files.find():
                if doc['md5'] == analysis_report["files"][key]["md5"]: 
                    db_match_count += 1 # if there is a match, it means MALLEVEL has scanned this file before, hence no need to update the database
            if db_match_count == 0: # if the file has never been scanned by MALLEVEL, insert it into database for record-keeping
                files.insert_one(db_file)
        except:
            pass
    sorted_analysis_report, sorted_analysis_results, (analysis_dangerous, analysis_safe) = sort_analysis_report_by_verdict(analysis_report)
    return sorted_analysis_report, sorted_analysis_results, (analysis_dangerous, analysis_safe)

# ADDED: SORT ANALYSIS REPORT SO DISPLAY WILL BE FROM DANGEROUS TO SAFE [BY LOKI SCORE FIRST, THEN BY ML PREDICTION]
def sort_analysis_report_by_verdict(analysis_report):
    """Function to sort the generated analysis report so that it will be presented in an order from Dangerous to Safe (by Loki score first, then by ML prediction)"""
    sorted_analysis_report = {}
    sorted_analysis_report["statistics"] = analysis_report["statistics"]
    analysis_dangerous, analysis_safe = 0, 0
    malicious_files = []
    dangerous, safe = {}, {}
    analysis_results = analysis_report["files"]
    for key, value in analysis_results.items():
        if value["verdict"] == "DANGEROUS":
            analysis_dangerous += 1
            dangerous[key] = value
        else:
            analysis_safe += 1
            safe[key] = value
    # SORT ALL ANALYSIS RESULTS IN ORDER OF VERDICT (BY LOKI SCORE FIRST, THEN HEURISTICS AND FINALLY ML PREDICTION) 
    sorted_dangerous = dict(sorted(dangerous.items(), key = lambda x: x[1]['signature_detection_score'], reverse=True))
    sorted_safe = dict(sorted(safe.items(), key = lambda x: x[1]['signature_detection_score'], reverse=True))
    sorted_analysis_results = {**sorted_dangerous, **sorted_safe}
    sorted_analysis_report["files"] = sorted_analysis_results
    sorted_analysis_report["statistics"]["file_dangerous"] = analysis_dangerous
    sorted_analysis_report["statistics"]["file_safe"] = analysis_safe
    malicious_files = list(sorted_dangerous.keys())
    sorted_analysis_report["statistics"]["malicious_files"] = malicious_files
    return sorted_analysis_report, sorted_analysis_results, (analysis_dangerous, analysis_safe)

# ADDED: INVOKE SPLUNK LOGGER TO SEND RELEVANT LOGS TO SPLUNK FOR THREAT ANALYSIS
def send_results_to_splunk(analysis_results, remote_logger):
    """Format Splunk logger for sending of relevant logs for analysis and visualization"""
    results_log_message = "\'%s\': %s"
    for key, value in analysis_results.items():
        do_remote_logging(remote_logger, "INFO", ["Results", results_log_message % (key, value)])

# THIS FUNCTION WAS ORIGINALLY FROM DEEPMALWAREDETECTOR TO EXTRACT IMPORTS, BUT SEEMS TO FIT BETTER IN LOKI FILE INFO
# SO THAT EVEN IF FILE IS DANGEROUS BASED ON SIGNATURE (NOT SENT TO ML), THE IMPORTS WILL STILL BE EXTRACTED
def imports_json(file_path):
    """Extracts imported modules within PE files to provide more information"""
    imports = {}
    try:
        exe = pefile.PE(file_path)
    except:
        return 'Parsing Error'
    try:
        for entry in exe.DIRECTORY_ENTRY_IMPORT:
            dll = str(entry.dll.decode('utf-8').lower())
            imports[dll] = []
            for func in entry.imports:
                if func.name is not None:
                    func_name = str(func.name.decode('utf-8').lower())
                    imports[dll].append(func_name)
                else:
                    func_ordinal = str(func.ordinal)
                    imports[dll].append(func_ordinal)
        exe.close()
        return imports
    except:
        return {}

def return_decoded_value(value):
    if type(value) is bytes:
        value = value.decode('utf-8')
    elif type(value) is not str:
        value = value.decode("ascii", "ignore")
    else:
        value = value
    return value.strip('\r\n')

# TO LOG ALL SIGNATURE INITIALIZATION ACTIONS BEFORE MALLEVEL STARTS SCANNING
def initialize_signature_loggers():
    """Initialize all loggers to log signature initialization actions before start of scan"""
    date_obj = dt.now()
    date_str = date_obj.strftime("%Y-%m-%d-%H-%M-%S")
    initialization_log_name = "mallevel-initialization-log-%s.log" % date_str
    initialization_log_path = os.path.join(INITIALIZATION_LOG_PATH, initialization_log_name)
    platform = platform_checker()
    hostname = hostname_checker(platform)
    logger = LokiLogger(initialization_log_path, hostname, platform, None)
    remote_logger = SplunkLogger(hostname, sourcetype = "mallevel_initialization_logs", token = SPLUNK_ANALYSIS_LOGS_TOKEN) # Only send logs to Splunk instance if alive; hence many tries and excepts to handle failed Splunk connections...
    do_remote_logging(remote_logger, "NOTICE", ["Init", "The MALLEVEL Server will also be sending logs to the Splunk instance at %s:%s" % (SPLUNK_HOST, SPLUNK_PORT)])
    return logger, remote_logger

# Function for MALLEVEL Server to connect to MALLEVEL Database (MongoDB). Can reduce total scanning time if submitted file has been scanned previously and saved in the Database.
def connect_to_mongodb(host = 'localhost', port = 27017): # set host and port as default MongoDB Values
    """Function for MALLEVEL Server to connect to MALLEVEL Database (MongoDB). Can reduce total scanning time if submitted file has been scanned previously and saved in the Database."""
    try:
        client = MongoClient(host = host, port = port, serverSelectionTimeoutMS = 2) # Set timeout to small value to reduce overall process duration (default is 30)
        db = client.mallevel # intialize database name as "mallevel"
        db_files = db.file_reports
        for doc in db_files.find(): # Check whether MongoDB service is running. If it is not running, then set db_files as None so other functions will not perform unexpectedly
            pass
    except:
        db_files = None
    finally:
        return db_files

# Prediction function for PE
def predict_pe(logger, remote_logger, file_path, file_name):
    """Prediction function for PEs that will use MDML model"""
    prediction_result = mdml.predict_file(logger, remote_logger, file_path, file_name) # Use MDML Framework as default ML Framework
    return prediction_result

# Prediction function for PDF  
# def predict_pdf(logger, remote_logger, file_path, file_name):
#     prediction_result = pdfml.predict_file(logger, remote_logger, file_path, file_name)
#     if prediction_result != {}:
#       logger.log(prediction_result, "FilePredict", "FILE: %s PREDICTION: %s " % (file_name, prediction_result))
#       do_remote_logging(remote_logger, prediction_result, ["FilePredict", "FILE: %s PREDICTION: %s " % (file_name, prediction_result)])
#     return prediction_result

# Prediction function for Office Documents
# def predict_office(logger, remote_logger, file_path, file_name):
#     prediction_result = officeml.predict_file(logger, remote_logger, file_path, file_name)
#     if prediction_result != {}:
#         logger.log(prediction_result, "FilePredict", "FILE: %s PREDICTION: %s " % (file_name, prediction_result))
#         do_remote_logging(remote_logger, prediction_result, ["FilePredict", "FILE: %s PREDICTION: %s " % (file_name, prediction_result)])
#     return prediction_result

# Added: Add support for extracting unnested and nested zip files for individual file analysis. By default, Loki is not capable of checking within ZIP archives.
# *** Only supports non-password-protected zip files; could possibly be extended to accept password inputs(?)
def extract_nested_zip(logger, remote_logger, zip_file, zip_folder):
    """Add support for extracting unnested and nested zip files for individual file analysis. By default, Loki is not capable of checking within ZIP archives."""
    zip_file_name = zip_file.split('\\')[-1] # for Windows Path Separator...
    # zip_file_name = zip_file.split('/')[-1] # for Linux Path Separator...
    try:
        Archive(zip_file).extractall(zip_folder) # try to extract the zip file without any password
        logger.log("INFO", "ZIPExtract", "Extracted zip file '%s' without any password" % zip_file_name)
        do_remote_logging(remote_logger, "INFO", ["ZIPExtract", "Extracted zip file '%s' without any password" % zip_file_name])
    except:
        logger.log("ERROR", "ZIPExtract", "Unable to perform extraction of zip file '%s'..." % zip_file_name)
        do_remote_logging(remote_logger, "ERROR", ["ZIPExtract", "Unable to perform extraction of zip file '%s'..." % zip_file_name])
    os.remove(zip_file)  
    for root, dirs, files in os.walk(zip_folder):
        for filename in files:
            if re.search(r'\.(7z|zip|bz2|gz)$', filename): # regex check for zip file extension in file name, in order to perform extraction
                fileSpec = os.path.join(root, filename)
                extract_nested_zip(logger, remote_logger, fileSpec, root)

# Added: To call the zip extractor function and return a list of all contained files
def get_compressed_files(logger, remote_logger, zip_file_path, zip_file_name):
    """To call the zip extractor function and return a list of all contained files"""
    zip_folder_name = zip_file_name.split('.')[0] + "__zip"
    zip_folder_path = os.path.join(UPLOAD_PATH, zip_folder_name) # Compressed files will be stored within a folder in the Flask uploads directory
    try:
        os.makedirs(zip_folder_path)
    except:
        shutil.rmtree(zip_folder_path)
        os.makedirs(zip_folder_path)
    zip_file_copy_name = "copy_" + zip_file_name
    zip_file_copy_path = os.path.join(UPLOAD_PATH, zip_file_copy_name) # to extract the ZIP file and keep a copy of unextracted zip file
    shutil.copy(zip_file_path, zip_file_copy_path)
    logger.log("INFO", "ZIPExtract", "Extracting zip files to '%s'..." % zip_folder_path)
    do_remote_logging(remote_logger, "INFO", ["ZIPExtract", "Extracting zip files to '%s'..." % zip_folder_path])
    try:
        extract_nested_zip(logger, remote_logger, zip_file_copy_path, zip_folder_path) # Unzip the zip files (including nested zip files) 
    except:
        pass
    file_paths = []
    for root, dirs, files in os.walk(zip_folder_path):
        file_paths.extend(os.path.join(root, file) for file in files)
    return file_paths # Return the entire list of all files stored within the zip file for individual scanning

# Added: General scan function to invoke Loki detection and ML prediction
def scan_file(logger, remote_logger, intense_scanner, file_path, original_filename, connect_mongodb):
    """General scan function to invoke Loki detection and ML prediction"""
    file_result = intense_scanner.scan_file(file_path, original_filename, connect_mongodb)
    prediction_result = None
    pe_heuristics_result = None
    try:
        file_name = file_result["file_name"]
    except:
        file_name = file_result["secured_file_name"]
    if "in_mongodb" in file_result.keys(): # If file was already scanned previously and its results are saved within the database, then straightaway retrieve the results
        file_type = file_result["file_type"]
        prediction_result = file_result["prediction"]
        heuristics_result = file_result["heuristics"]
        return file_name, file_type, file_result, heuristics_result, prediction_result
    file_type = file_result["file_type"]
    # if file_type == "EXE": #uncomment if want imports info for exe
        # file_result["file_imports"] = imports_json(file_path) 
    # Based on Loki file type checker, "EXE" <--> Portable Executables (4A 5D)
    if file_result["verdict"] == "SAFE": # If file has not been detected by signature-based detection, send it for heuristics-based detection (only PEs)
        if file_type == "EXE":
            pe_heuristics_result, pe_heuristics_alerts = pe_heuristics_detection(logger, remote_logger, file_path, file_name) # For PEs: Sig-Based Detection --> Heur-Based Detection --> ML-Based Detection
            if pe_heuristics_result == "SAFE": # If file has not been detected by heuristics-based detection, send it for ML-based detection
                prediction_result = predict_pe(logger, remote_logger, file_path, file_name) # Javier's ML Framework for PE Prediction
            else:
                file_result["verdict"] = pe_heuristics_result
                reasons = file_result["reasons"]
                for pe_heuristic_alert in pe_heuristics_alerts: # Add heuristic analysis information to report if PE is dangerous based on heuristical analysis
                    reasons.append(pe_heuristic_alert)
                file_result["reasons"] = reasons
        # elif file_type == "PDF":
        #     prediction_result = predict_pdf(logger, remote_logger, file_path, file_name) # Mark's ML Framework for PDF Prediction
        # elif file_type in ['Office', 'DOC', 'OLE']:
        #     prediction_result = predict_office(logger, remote_logger, file_path, file_name) # Mark's ML Framework for Office Prediction
    return file_name, file_type, file_result, pe_heuristics_result, prediction_result

# Added: General function to handle scanning of files compressed within zip files
def scan_compressed_files(logger, remote_logger, intense_scanner, compressed_file_paths, connect_mongodb):
    """General function to handle scanning of files compressed within zip files"""
    zip_file_results = {}
    zip_total_score = 0
    zip_reasons = []
    compressed_file_name_list = []
    for compressed_file_path in compressed_file_paths:    
        compressed_file_name = compressed_file_path.split('\\')[-1] # for Windows Path Separator...
        # compressed_file_name = compressed_file_path.split('/')[-1] # for Linux Path Separator...
        compressed_file_name_list.append(compressed_file_name)
        zip_file_name, zip_file_type, zip_file_result, zip_heuristics_result, zip_prediction_result = scan_file(logger, remote_logger, intense_scanner, compressed_file_path, compressed_file_name, connect_mongodb)
        zip_file_results[zip_file_name] = zip_file_result
        if zip_file_result["signature_detection_score"] > 0:
            zip_total_score += zip_file_result["signature_detection_score"] # sum up zip file score by adding the score of individual compressed files
            zip_reasons.append("%s has a score of %s" % (zip_file_name, zip_file_result['signature_detection_score'])) # append the reason for score addition
        zip_file_results[zip_file_name]["heuristics"] = zip_heuristics_result 
        zip_file_results[zip_file_name]["prediction"] = zip_prediction_result 
    return zip_file_results, zip_total_score, zip_reasons, compressed_file_name_list

# Function for file classification based on total score
def get_message_type(total_score):
    """Function for file classification based on total score"""
    if total_score >= 70:
        return "DANGEROUS"
    else:
        return "SAFE"

# Obtain SHA256 hash of specified file    
def calculate_sha256(file_path, block_size=65536):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

# Convert machine-learning datasets from CSV to HTML, for preview in web UI
def csv_to_html(dataset_path, framework):
    if framework == "PE":
        preview_dataset = pd.read_csv(dataset_path, nrows=20).drop(['id', 'sha256'],axis=1)
    else:
        preview_dataset = pd.read_csv(dataset_path, nrows=20)
    preview_dataset_html = preview_dataset.to_html()
    return preview_dataset_html