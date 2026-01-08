import os
from constants import IOCS_DIR_PATH
from remote_logging import do_remote_logging
import requests
import codecs

PHISHTANK_JSON_URL = "http://data.phishtank.com/data/online-valid.json"
PHISHTANK_PROCESSED_URLS_FILE_NAME = "phishing-url-iocs.txt"

# To read PhishTank latest JSON data (of phishing URLs) and process it for parsing later on by MALLEVEL scanner (URL;reason)
def download_phishing_urls(logger, remote_logger):
    processed_urls_file_path = os.path.join(IOCS_DIR_PATH, PHISHTANK_PROCESSED_URLS_FILE_NAME)
    try:
        logger.log("INFO", "External-Upgrader", "Downloading %s ..." % PHISHTANK_JSON_URL)
        do_remote_logging(remote_logger, "INFO", ["External-Upgrader", "Downloading %s ..." % PHISHTANK_JSON_URL])
        with requests.get(PHISHTANK_JSON_URL) as phishtank_data:
            phishtank_data_json = phishtank_data.json()
            logger.log("INFO", "External-Upgrader", "Processing PhishTank URLs...")
            do_remote_logging(remote_logger, "INFO", ["External-Upgrader", "Processing PhishTank URLs..."])
            with codecs.open(processed_urls_file_path, 'w', encoding='utf8') as processed_urls_file:
                for phishtank_data_row in phishtank_data_json:
                    reason = "Phishing URL blacklisted in PhishTank"
                    line = "%s;%s\n" % (phishtank_data_row["url"], reason)
                    processed_urls_file.write(line)
        logger.log("INFO", "External-Upgrader", "Finished processing PhishTank URLs...")
        do_remote_logging(remote_logger, "INFO", ["External-Upgrader", "Finished processing PhishTank URLs..."])        
    except:
        logger.log("ERROR", "External-Upgrader", "Error while processing PhishTank URLs (possibly due to rate limiting)...")
        do_remote_logging(remote_logger, "ERROR", ["External-Upgrader", "Error while processing PhishTank URLs (possibly due to rate limiting)..."])
