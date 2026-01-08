from constants import *
from remote_logging import do_remote_logging
from general_functions import platform_checker, initialize_signature_loggers
import codecs
from lib.helpers import *
from loki_objects import LOKIUpdater
import yara

# TO COMPILE YARA RULES REQUIRED FOR LOKI SIGNATURE-BASED DETECTION
# PREVIOUSLY THE YARA RULES WERE INITIALIZED EVERY TIME A SCAN WAS EXECUTED
# IT IS VERY INEFFICIENT, AND THERE ARE ALSO ERRORS OF DUPLICATED IDENTIFIER DURING COMPILING
# E.G. ERROR: line 274457: duplicated identifier "SUSP_EXPL_Confluence_RCE_CVE_2021_26084_Indicators_Sep21"
# HENCE INITIALIZING ALL SIGNATURES BEFORE MALLEVEL STARTS WILL BE A BETTER OPTION
def initialize_yara_rules(logger, remote_logger):
    """To initialize all YARA rule IOCs from Loki"""
    yaraRules = ""
    final_yara_rules_list = []
    dummy = ""
    rule_count = 0
    try:
        logger.log("INFO", "Init", "Processing YARA rules folder {0}".format(YARA_DIR_PATH))
        do_remote_logging(remote_logger, "INFO", ["Init", "Processing YARA rules folder {0}".format(YARA_DIR_PATH)])
        for root, directories, files in os.walk(YARA_DIR_PATH, onerror=None, followlinks=False):
            for file in files:
                try:
                    # Full Path
                    yaraRuleFile = os.path.join(root, file)
                    # Skip hidden, backup or system related files
                    if file.startswith(".") or file.startswith("~") or file.startswith("_"):
                        continue
                    # Extension
                    extension = os.path.splitext(file)[1].lower()
                    # Skip all files that don't have *.yar or *.yara extensions
                    if extension != ".yar" and extension != ".yara":
                        continue
                    with open(yaraRuleFile, 'r') as yfile:
                        yara_rule_data = yfile.read()
                    # Test Compile
                    try:
                        compiledRules = yara.compile(source=yara_rule_data, externals={
                            'filename': dummy,
                            'filepath': dummy,
                            'extension': dummy,
                            'filetype': dummy,
                            'md5': dummy,
                            'owner': dummy,
                        })
                        # self.logger.log("DEBUG", "Init", "Initializing Yara rule %s" % file)
                        rule_count += 1
                    except Exception as e:
                        logger.log("ERROR", "Init", "Error while initializing Yara rule %s ERROR: %s" % (file, sys.exc_info()[1]))
                        do_remote_logging(remote_logger, "ERROR", ["Init", "Error while initializing Yara rule %s ERROR: %s" % (file, sys.exc_info()[1])])
                        continue
                    # Add the rule
                    yaraRules += yara_rule_data
                except Exception as e:
                    logger.log("ERROR", "Init", "Error reading signature file %s ERROR: %s" % (yaraRuleFile, sys.exc_info()[1]))
                    do_remote_logging(remote_logger, "ERROR", ["Init", "Error reading signature file %s ERROR: %s" % (yaraRuleFile, sys.exc_info()[1])])
        # Compile
        try:
            logger.log("INFO", "Init", "Initializing all YARA rules at once (composed string of all rule files)")
            do_remote_logging(remote_logger, "INFO", ["Init", "Initializing all YARA rules at once (composed string of all rule files)"])
            compiledRules = yara.compile(source=yaraRules, externals={
                'filename': dummy,
                'filepath': dummy,
                'extension': dummy,
                'filetype': dummy,
                'md5': dummy,
                'owner': dummy,
            })
            logger.log("INFO", "Init", "Initialized %d Yara rules" % rule_count)
            do_remote_logging(remote_logger, "INFO", ["Init", "Initialized %d Yara rules" % rule_count])
        except Exception as e:
            logger.log("ERROR", "Init", "Error during YARA rule compilation ERROR: %s - please fix the issue in the rule set" % sys.exc_info()[1])
            do_remote_logging(remote_logger, "ERROR", ["Init", "Error during YARA rule compilation ERROR: %s - please fix the issue in the rule set" % sys.exc_info()[1]])
        # Add as Lokis YARA rules
        final_yara_rules_list.append(compiledRules)
    except Exception as e:
        logger.log("ERROR", "Init", "Error reading signature folder /signatures/")
        do_remote_logging(remote_logger, "ERROR", ["Init", "Error reading signature folder /signatures/"])
    finally:
        return final_yara_rules_list

# File Name IOCs (all files in iocs that contain 'filename')
def initialize_filename_iocs(logger, remote_logger):
    """To initialize all filename IOCs from Loki"""
    try:
        filename_iocs = []
        os_platform = platform_checker()
        for ioc_filename in os.listdir(IOCS_DIR_PATH):
            if 'filename' in ioc_filename:
                with codecs.open(os.path.join(IOCS_DIR_PATH, ioc_filename), 'r', encoding='utf-8') as file:
                    lines = file.readlines()
                    # Last Comment Line
                    last_comment = ""
                    # Initialize score variable
                    score = 0
                    # Initialize empty description
                    desc = ""
                    for line in lines:
                        try:
                            # Empty
                            if re.search(r'^[\s]*$', line):
                                continue
                            # Comments
                            if re.search(r'^#', line):
                                last_comment = line.lstrip("#").lstrip(" ").rstrip("\n")
                                continue
                            # Elements with description
                            if ";" in line:
                                line = line.rstrip(" ").rstrip("\n\r")
                                row = line.split(';')
                                regex = row[0]
                                score = row[1]
                                if len(row) > 2:
                                    regex_fp = row[2]
                                desc = last_comment
                            # Elements without description
                            else:
                                regex = line
                            # Replace environment variables
                            regex = replaceEnvVars(regex)
                            # OS specific transforms
                            regex = transformOS(regex, os_platform)
                            # If false positive definition exists
                            regex_fp_comp = None
                            if 'regex_fp' in locals():
                                # Replacements
                                regex_fp = replaceEnvVars(regex_fp)
                                regex_fp = transformOS(regex_fp, os_platform)
                                # String regex as key - value is compiled regex of false positive values
                                regex_fp_comp = re.compile(regex_fp)
                            # Create dictionary with IOC data
                            fioc = {'regex': re.compile(regex), 'score': score, 'description': desc, 'regex_fp': regex_fp_comp}
                            filename_iocs.append(fioc)
                        except Exception as e:
                            logger.log("ERROR", "Init", "Error reading line: %s" % line)
                            do_remote_logging(remote_logger, "ERROR", ["Init", "Error reading line: %s" % line])
    except Exception as e:
        if 'ioc_filename' in locals():
            logger.log("ERROR",  "Init", "Error reading IOC file: %s" % ioc_filename)
            do_remote_logging(remote_logger, "ERROR", ["Init", "Error reading IOC file: %s" % ioc_filename])
        else:
            logger.log("ERROR",  "Init", "Error reading files from IOC folder: %s" % IOCS_DIR_PATH)  
            logger.log("ERROR",  "Init", "Please make sure that you cloned the repo or downloaded the sub repository: "
                                            "See https://github.com/Neo23x0/Loki/issues/51")
            do_remote_logging(remote_logger, "ERROR", ["Init", "Error reading files from IOC folder: %s" % IOCS_DIR_PATH])
            do_remote_logging(remote_logger, "ERROR", ["Init", "Please make sure that you cloned the repo or downloaded the sub repository: "
                                            "See https://github.com/Neo23x0/Loki/issues/51"])
    finally:
        logger.log("INFO", "Init", "File Name Characteristics initialized with %s regex patterns" % len(filename_iocs))
        do_remote_logging(remote_logger, "INFO", ["Init", "File Name Characteristics initialized with %s regex patterns" % len(filename_iocs)])
        return filename_iocs

# Hash IOCs
def initialize_hashes(logger, remote_logger):
    """To initialize all hash IOCs from Loki"""
    # Loki's hardcoded whitelist of hashes
    HASH_WHITELIST = [# Empty file
                        int('d41d8cd98f00b204e9800998ecf8427e', 16),
                        int('da39a3ee5e6b4b0d3255bfef95601890afd80709', 16),
                        int('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 16),
                        # One byte line break file (Unix) 0x0a
                        int('68b329da9893e34099c7d8ad5cb9c940', 16),
                        int('adc83b19e793491b1c6ea0fd8b46cd9f32e592fc', 16),
                        int('01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b', 16),
                        # One byte line break file (Windows) 0x0d0a
                        int('81051bcc2cf1bedf378224b0a93e2877', 16),
                        int('ba8ab5a0280b953aa97435ff8946cbcbb2755a27', 16),
                        int('7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6', 16),
                        ]
    false_positive = False
    hashes_md5 = {}
    hashes_sha1 = {}
    hashes_sha256 = {}
    false_hashes = {}
    try:
        for ioc_filename in os.listdir(IOCS_DIR_PATH):
            if 'hash' in ioc_filename: # any file with "hash" in filename will be treated as a file storing hashes
                if false_positive and 'falsepositive' not in ioc_filename:
                    continue
                with codecs.open(os.path.join(IOCS_DIR_PATH, ioc_filename), 'r', encoding='utf-8') as file:
                    lines = file.readlines()
                    for line in lines:
                        try:
                            if re.search(r'^#', line) or re.search(r'^[\s]*$', line):
                                continue
                            row = line.split(';')
                            hash = row[0].lower()
                            comment = row[1].rstrip(" ").rstrip("\n")
                            # Empty File Hash
                            if hash in HASH_WHITELIST:
                                continue
                            # Else - check which type it is
                            if len(hash) == 32:
                                hashes_md5[int(hash, 16)] = comment
                            if len(hash) == 40:
                                hashes_sha1[int(hash, 16)] = comment
                            if len(hash) == 64:
                                hashes_sha256[int(hash, 16)] = comment
                            if false_positive:
                                false_hashes[int(hash, 16)] = comment
                        except Exception as e:
                            logger.log("ERROR", "Init", "Cannot read line: %s" % line)
                            do_remote_logging(remote_logger, "ERROR", ["Init", "Cannot read line: %s" % line])
        # create sorted lists with just the integer values of the hashes for quick binary search 
        hashes_md5_list = list(hashes_md5.keys())
        hashes_md5_list.sort()
        hashes_sha1_list = list(hashes_sha1.keys())
        hashes_sha1_list.sort()
        hashes_sha256_list = list(hashes_sha256.keys())
        hashes_sha256_list.sort()
        logger.log("INFO", "Init", "Malicious MD5 Hashes initialized with %s hashes" % len(hashes_md5_list))
        logger.log("INFO", "Init", "Malicious SHA1 Hashes initialized with %s hashes" % len(hashes_sha1_list))
        logger.log("INFO", "Init", "Malicious SHA256 Hashes initialized with %s hashes" % len(hashes_sha256_list))
        do_remote_logging(remote_logger, "INFO", ["Init", "Malicious MD5 Hashes initialized with %s hashes" % len(hashes_md5_list)])
        do_remote_logging(remote_logger, "INFO", ["Init", "Malicious SHA1 Hashes initialized with %s hashes" % len(hashes_sha1_list)])
        do_remote_logging(remote_logger, "INFO", ["Init", "Malicious SHA256 Hashes initialized with %s hashes" % len(hashes_sha256_list)])
    except Exception as e:
        logger.log("ERROR", "Init", "Error reading Hash file: %s" % ioc_filename)
        do_remote_logging(remote_logger, "ERROR", ["Init", "Error reading Hash file: %s" % ioc_filename])
    finally:
        return hashes_md5, hashes_md5_list, hashes_sha1, hashes_sha1_list, hashes_sha256, hashes_sha256_list

# Filetype Signatures for Easy Identification        
def initialize_filetype_magics(logger, remote_logger):
    """Filetype Signatures for Easy Identification  """   
    filetype_magics_file = os.path.join(MISC_DIR_PATH, "file-type-signatures.txt") # file containing signatures to identify file type
    max_filetype_magics = 0
    filetype_magics = {}
    try:
        with open(filetype_magics_file, 'r') as config:
            lines = config.readlines()
        for line in lines:
            try:
                if re.search(r'^#', line) or re.search(r'^[\s]*$', line) or ";" not in line:
                    continue
                ( sig_raw, description ) = line.rstrip("\n").split(";")
                sig = re.sub(r' ', '', sig_raw)
                if len(sig) > max_filetype_magics:
                    max_filetype_magics = len(sig)
                filetype_magics[sig] = description
            except Exception as e:
                logger.log("ERROR", "Init", "Cannot read line: %s" % line)
                do_remote_logging(remote_logger, "ERROR", ["Init", "Cannot read line: %s" % line])
    except Exception as e:
        logger.log("ERROR", "Init", "Error reading Hash file: %s" % filetype_magics_file)
        do_remote_logging(remote_logger, "ERROR", ["Init", "Error reading Hash file: %s" % filetype_magics_file])
    finally:
        return filetype_magics, max_filetype_magics

# Added: To initialize the CSCB from MalwareBazaar (which is an enhancement)
def initialize_code_signing_certificate_blocklist(logger, remote_logger):
    """Code Signing Certificate Blocklist based on Serial Numbers """
    cscb_dict = {}
    cscb_filename = "codesign-iocs.txt"   
    with codecs.open(os.path.join(IOCS_DIR_PATH, cscb_filename), 'r', encoding='utf-8') as file:
        lines = file.readlines()
        for line in lines:
            try:
                row = line.split(';')
                serial_number = row[0].lower()
                reason = row[1].rstrip("\n").rstrip("\r")
                cscb_dict[serial_number] = reason
            except Exception as e:
                logger.log("ERROR", "Init", "Cannot read line: %s" % line)
                do_remote_logging(remote_logger, "ERROR", ["Init", "Cannot read line: %s" % line])
    logger.log("INFO", "Init", "Malicious Code Signing Certificates initialized with %s certificates" % len(cscb_dict))
    do_remote_logging(remote_logger, "INFO", ["Init", "Malicious Code Signing Certificates initialized with %s certificates" % len(cscb_dict)])
    return cscb_dict

# Added: To initialize blacklisted URLs obtained from various sources, e.g. PhishTank, AlienVault OTX
def initialize_blacklist_url_iocs(logger, remote_logger):
    phishtank_url_iocs_filename = "phishing-url-iocs.txt"
    otx_url_iocs_filename = "otx-url-updated-iocs.txt"
    url_iocs_filenames = [phishtank_url_iocs_filename, otx_url_iocs_filename]
    urls_dict = {}
    for url_iocs_filename in url_iocs_filenames:
        with codecs.open(os.path.join(IOCS_DIR_PATH, url_iocs_filename), 'r', encoding='utf-8') as url_iocs:
            lines = url_iocs.readlines()
            for line in lines:
                try:
                    row = line.split(';')
                    url = row[0].lower()
                    reason = row[1].rstrip("\n").rstrip("\r")
                    urls_dict[url] = reason
                except Exception as e:
                    logger.log("ERROR", "Init", "Cannot read line: %s in file: %s" % (line, url_iocs_filename))
                    do_remote_logging(remote_logger, "ERROR", ["Init", "Cannot read line: %s in file: %s" %  (line, url_iocs_filename)])
    logger.log("INFO", "Init", "Malicious URLs initialized with %s URLs" % len(urls_dict))
    return urls_dict

# Main function to invoke other initialization functions, to initialize all signatures
# Runs everytime server is started. It also runs after every signature update to ensure the new signatures are loaded.
def initialize_all_signatures(logger, remote_logger):
    """Main function to invoke other initialization functions, to initialize all signatures"""
    # Initialize signatures for Loki scanning; hashes, YARA rules, magics, etc.
    yara_rules = initialize_yara_rules(logger, remote_logger)
    filename_iocs = initialize_filename_iocs(logger, remote_logger)
    hashes_md5, hashes_md5_list, hashes_sha1, hashes_sha1_list, hashes_sha256, hashes_sha256_list = initialize_hashes(logger, remote_logger)
    filetype_magics, max_filetype_magics = initialize_filetype_magics(logger, remote_logger)
    code_signing_blocklist = initialize_code_signing_certificate_blocklist(logger, remote_logger)
    signatures = [yara_rules, filename_iocs, hashes_md5, hashes_md5_list, hashes_sha1, hashes_sha1_list, hashes_sha256, hashes_sha256_list, filetype_magics, max_filetype_magics, code_signing_blocklist]
    # Initialize blacklisted URLs for URL lookup to perform check, before relying on ML
    blacklisted_urls = initialize_blacklist_url_iocs(logger, remote_logger)
    return signatures, blacklisted_urls

# Initialize loggers and initialize all virus signatures and blacklisted URLs
init_logger, init_remote_logger = initialize_signature_loggers() # to initialize logger for logging initialization of signatures    
INITIALIZED_SIGNATURES, INITIALIZED_BLACKLISTED_URLS = initialize_all_signatures(init_logger, init_remote_logger)