import os

# Allowed extensions for file submissions via Flask - can modify based on use case
# This is currently not used...
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'exe', 'tmp', 
                      'dll', 'bin', 'doc', 'xls', 'csv', "asp", "vbs", "ps1", 
                      "bas", "bat", "js", "vb", "vbe", "wsc", "wsf", "wsh", 
                      ".jsp", "jspx", "php", "asp", "aspx", "psd1", "psm1", 
                      "ps1xml", "clixml", "psc1", "pssc", "pl"}

# MALLEVEL working directory
MALLEVEL_PATH = os.path.dirname(os.path.realpath(__file__))

# Path to MALLEVEL Hashes
IOCS_DIR_PATH = os.path.join(MALLEVEL_PATH, "signature-base", "iocs")

# Path to MALLEVEL Misc Signatures
MISC_DIR_PATH = os.path.join(MALLEVEL_PATH, "signature-base", "misc")

# Path to MALLEVEL YARA Rulesets
YARA_DIR_PATH = os.path.join(MALLEVEL_PATH, "signature-base", "yara")

# Path to MALLEVEL analysis logs
ANALYSIS_LOG_PATH = os.path.join(MALLEVEL_PATH, "logs", "analysis")

# Path to MALLEVEL update logs
UPDATE_LOG_PATH = os.path.join(MALLEVEL_PATH, "logs", "update")

# Path to MALLEVEL initialization logs (on YARA rules, hashes, etc.)
INITIALIZATION_LOG_PATH = os.path.join(MALLEVEL_PATH, "logs", "initialization")

# Path to user-uploaded files, stored within MALLEVEL working directory
UPLOAD_PATH = os.path.join(MALLEVEL_PATH, "uploads")

# Path to admin-uploaded files for hashing and whitelisting, stored within MALLEVEL working directory
WHITELIST_PATH = os.path.join(MALLEVEL_PATH, "whitelist")

# Path to quarantined files, stored within MALLEVEL working directory
QUARANTINE_PATH = os.path.join(MALLEVEL_PATH, "quarantine")

# Path to MALLEVEL analysis reports
ANALYSIS_REPORT_PATH = os.path.join(MALLEVEL_PATH, "reports")

# Predefined MALLEVEL Evil Extensions
EVIL_EXTENSIONS = [".vbs", ".ps", ".ps1", ".rar", ".tmp", ".bas", ".bat", ".chm", ".cmd", ".com", ".cpl",
                   ".crt", ".dll", ".exe", ".hta", ".js", ".lnk", ".msc", ".ocx", ".pcd", ".pif", ".pot", ".pdf",
                   ".reg", ".scr", ".sct", ".sys", ".url", ".vb", ".vbe", ".wsc", ".wsf", ".wsh", ".ct", ".t",
                   ".input", ".war", ".jsp", ".jspx", ".php", ".asp", ".aspx", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt",
                   ".pptx", ".tmp", ".log", ".dump", ".pwd", ".w", ".txt", ".conf", ".cfg", ".conf", ".config", ".psd1",
                   ".psm1", ".ps1xml", ".clixml", ".psc1", ".pssc", ".pl", ".www", ".rdp", ".jar", ".docm", ".sys"]

SCRIPT_EXTENSIONS = [".asp", ".vbs", ".ps1", ".bas", ".bat", ".js", ".vb", ".vbe", ".wsc", ".wsf",
                     ".wsh", ".jsp", ".jspx", ".php", ".asp", ".aspx", ".psd1", ".psm1", ".ps1xml", ".clixml", ".psc1",
                     ".pssc", ".pl"]

SCRIPT_TYPES = ["VBS", "PHP", "JSP", "ASP", "BATCH"]

SUPPORTED_ZIP_EXTRACTION_TYPES = ["ZIP", "7Zip", "GZIP", "BZip2"] # IMPORTANT: MUST BE CASE-SENSITIVE TO MATCH LOKI FILE MAGICS

# Constants for MDML Framework
MDML_MAIN_PATH = os.path.join(MALLEVEL_PATH, "mdml_files") # Path to all MDML Files
MDML_DATASET_PATH = os.path.join(MDML_MAIN_PATH, "datasets/static.csv") # Path to MDML static dataset
MDML_STATIC_MODEL_PATH = os.path.join(MDML_MAIN_PATH, "models/static.joblib") # Path to MDML static model
MDML_STATIC_SCALER_MODEL_PATH = os.path.join(MDML_MAIN_PATH, "models/static_scaler.joblib") # Path to MDML static scaler
MDML_TARGET_NAMES_PATH = os.path.join(MDML_MAIN_PATH, "labels/static.joblib") # Path to MDML classification labels (e.g. benign, win32 malware)
MDML_FEATURES_PATH = os.path.join(MDML_MAIN_PATH, "features/static.joblib") # Path to MDML features
MDML_YARA_RULES_PATH = os.path.join(MDML_MAIN_PATH, "auxiliary/Yara rules") # Path to MDML YARA rules
MDML_MAGIC_PATH = os.path.join(MDML_MAIN_PATH, "auxiliary/Magic/magic.mgc")

# Constants for PDF ML Framework
PDFML_MAIN_PATH = os.path.join(MALLEVEL_PATH, "pdfml_files")
# PDFML_DATASET_PATH = os.path.join(PDFML_MAIN_PATH, "dataset/data.csv")
PDFML_MODEL_PATH = os.path.join(PDFML_MAIN_PATH, "models") # set this constant to a path containing the PDF ML models in pickle format. (Should be named xxxxx.model)
# PDFML_FEATURES_PATH = os.path.join(PDFML_MAIN_PATH, "model/features")

# Constants for URL ML Framework
URLML_MAIN_PATH = os.path.join(MALLEVEL_PATH, "urlml_files")
URLML_MODEL_PATH = os.path.join(URLML_MAIN_PATH, "models")
URLML_DATASET_PATH = os.path.join(URLML_MAIN_PATH, "datasets/url_sample.csv")

# Constants for Office ML Framework
OFFICEML_MAIN_PATH = os.path.join(MALLEVEL_PATH, "officeml_files")
OFFICEML_MODEL_PATH = os.path.join(OFFICEML_MAIN_PATH, "models")
OFFICEML_DATASET_PATH = os.path.join(OFFICEML_MAIN_PATH, "datasets/office_sample.csv")

# Splunk Credentials and Configurations
SPLUNK_UPDATE_LOGS_TOKEN = "REDACTED" # token for sourcetype mallevel_update_logs
SPLUNK_ANALYSIS_LOGS_TOKEN = "REDACTED" # token for sourcetype mallevel_analysis_logs
SPLUNK_RESULTS_LOGS_TOKEN = "REDACTED" # token for sourcetype mallevel_results_logs
SPLUNK_HOST = '127.0.0.1'
SPLUNK_PORT = 8088

# MongoDB Configurations
MONGODB_HOST = 'localhost'
MONGODB_PORT = 27017

# Choose whether to fetch signatures from external sources during updates
# If True, it fetches Loki default signatures, MalwareBazaar SHA256 hashes and OTX IOCs
# If False, it only fetches Loki default signatures
UPDATE_EXTERNAL_SIGNATURES = False

# Replace with own OTX API Key (requires account sign up) for fetching of IOCs, to update existing signature files
OTX_API_KEY = "REDACTED" 

# Sample encryption key for agent API key. Note: This should be placed in a secure location, but for demonstration purposes, it will just be placed in this file.
XOR_ENCRYPTION_KEY = "sample_xor_encryption_key"