from splunk_handler import SplunkHandler
from datetime import datetime
import logging
from constants import SPLUNK_HOST, SPLUNK_PORT

logging.basicConfig(level = logging.INFO)

# RECONFIGURING LOG LEVELS FOR SPLUNK LOGGER TO MATCH MALLEVEL FILE CLASSIFICATION
DANGEROUS = 100
RESULTS = 60
ERROR = 40
INFO = 20
DEBUG = 10
SAFE = 25
WARNING = 35

def dangerous(msg, *args, **kwargs):
    if logging.getLogger('splunk').isEnabledFor(DANGEROUS):
        logging.log(DANGEROUS, msg)
        
def results(msg, *args, **kwargs):
    if logging.getLogger('splunk').isEnabledFor(RESULTS):
        logging.log(RESULTS, msg) 
         
def safe(msg, *args, **kwargs):
    if logging.getLogger('splunk').isEnabledFor(SAFE):
        logging.log(SAFE, msg)     

def info(msg, *args, **kwargs):
    if logging.getLogger('splunk').isEnabledFor(INFO):
        logging.log(INFO, msg)  
        
def error(msg, *args, **kwargs):
    if logging.getLogger('splunk').isEnabledFor(ERROR):
        logging.log(ERROR, msg)  
        
def warning(msg, *args, **kwargs):
    if logging.getLogger('splunk').isEnabledFor(WARNING):
        logging.log(WARNING, msg)  
        
def debug(msg, *args, **kwargs):
    if logging.getLogger('splunk').isEnabledFor(DEBUG):
        logging.log(DEBUG, msg)  


class SplunkLogger(object):
    
    def __init__(self, hostname, sourcetype, token):
        self.hostname = hostname
        self.sourcetype = sourcetype
        self.token = token
        self.logger = self.initialize_splunk_logger() # COMMENT OUT THIS LINE TO DECIPHER ANY ROOT ERRORS
        self.log_template = u"[" + self.getTimestamp() + "] " + self.hostname + " MALLEVEL: {0}: MODULE: {1} MESSAGE: {2}"

    def initialize_splunk_logger(self):
        return None # to disable remote logging temporarily
        splunk = SplunkHandler(
            host=SPLUNK_HOST, # Replace with own Splunk instance IP
            port=SPLUNK_PORT, # Replace with own Splunk instance port
            token=self.token, # Replace with own Splunk instance token
            index='main',
            #allow_overrides=True # whether to look for _<param in log data (ex: _index)
            #debug=True # whether to print module activity to stdout, defaults to False
            #flush_interval=15.0, # send batch of logs every n sec, defaults to 15.0, set '0' to block thread & send immediately
            #force_keep_ahead=True # sleep instead of dropping logs when queue fills
            #hostname=hostname, # manually set a hostname parameter, defaults to socket.gethostname()
            #protocol='http', # set the protocol which will be used to connect to the splunk host
            #proxies={
            #           'http': 'http://10.10.1.10:3128',
            #           'https': 'http://10.10.1.10:1080',
            #         }, set the proxies for the session request to splunk host
            #
            #queue_size=5000, # a throttle to prevent resource overconsumption, defaults to 5000, set to 0 for no max
            #record_format=True, whether the log format will be json
            #retry_backoff=1, the requests lib backoff factor, default options will retry for 1 min, defaults to 2.0
            retry_count=0, # number of retry attempts on a failed/erroring connection, defaults to 5
            source='MALLEVEL', # manually set a source, defaults to the log record.pathname
            sourcetype=self.sourcetype, # manually set a sourcetype, defaults to 'text'
            verify=False # turn SSL verification on or off, defaults to True
            #timeout=60, # timeout for waiting on a 200 OK from Splunk server, defaults to 60s
        )
        
        logger = logging.getLogger(self.sourcetype)
        logger.addHandler(splunk)
        logger.propagate = False
        
        logger.dangerous = dangerous
        logger.results = results
        logger.safe = safe
        logger.info = info
        logger.error = error
        logger.warning = warning
        logger.debug = debug

        logger.setLevel(logging.DEBUG)
        
        return logger # Return Splunk logger

    # Various wrapper functions for Splunk logger to log messages
    def dangerous(self, template_args):
        self.logger.setLevel(DANGEROUS)
        message = self.log_template.format("Dangerous", template_args[0], template_args[1]) 
        self.logger.log(DANGEROUS, message)

    def results(self, template_args):
        self.logger.setLevel(RESULTS)
        message = self.log_template.format("Results", template_args[0], template_args[1])  
        self.logger.log(RESULTS, message)
        
    def safe(self, template_args):
        self.logger.setLevel(SAFE) 
        message = self.log_template.format("Safe", template_args[0], template_args[1]) 
        self.logger.log(SAFE, message)
        
    def info(self, template_args):
        self.logger.setLevel(SAFE) 
        message = self.log_template.format("Info", template_args[0], template_args[1]) 
        self.logger.log(SAFE, message)
        
    def error(self, template_args):
        self.logger.setLevel(ERROR) 
        message = self.log_template.format("Error", template_args[0], template_args[1]) 
        self.logger.log(ERROR, message)        
        
    def warning(self, template_args):
        self.logger.setLevel(WARNING) 
        message = self.log_template.format("Warning", template_args[0], template_args[1]) 
        self.logger.log(WARNING, message)  
        
    def debug(self, template_args):
        self.logger.setLevel(DEBUG) 
        message = self.log_template.format("Debug", template_args[0], template_args[1]) 
        self.logger.log(DEBUG, message)   
        
    # Get current timestamp, to include in log messages    
    def getTimestamp(self):
        date_obj = datetime.now()
        date_str = date_obj.strftime("%Y-%m-%d %H:%M:%S")
        return date_str   
    
