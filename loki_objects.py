from datetime import datetime
import os
import codecs
from urllib.request import urlopen #For python 3.5
import shutil
import zipfile
import io
from sys import platform as _platform
from constants import *
from remote_logging import do_remote_logging

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


class LOKIUpdater(object):

    # Incompatible signatures
    INCOMPATIBLE_RULES = []

    UPDATE_URL_SIGS = [
        "https://github.com/Neo23x0/signature-base/archive/master.zip",
        "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip"
    ]
    
    UPDATE_URL_LOKI = "https://api.github.com/repos/Neo23x0/Loki/releases/latest"
    
    def __init__(self, logger, remote_logger, application_path):
        self.logger = logger
        self.remote_logger = remote_logger # Added: Splunk logging
        self.application_path = application_path  

    def update_signatures(self, clean=False):
        logging = True
        for sig_url in self.UPDATE_URL_SIGS:
            # Downloading current repository
            if logging == True:
                self.logger.log("INFO", "Upgrader", "Downloading %s ..." % sig_url)
                do_remote_logging(self.remote_logger, "INFO", ["Upgrader", "Downloading %s ..." % sig_url])
            response = urlopen(sig_url)
            
            sigDir = os.path.join(self.application_path, os.path.abspath('signature-base/'))
            if clean:
                if logging == True:
                    self.logger.log("INFO", "Upgrader", "Cleaning directory '%s'" % sigDir)
                    do_remote_logging(self.remote_logger, "INFO", ["Upgrader", "Cleaning directory '%s'" % sigDir])
                shutil.rmtree(sigDir)
            for outDir in ['', 'iocs', 'yara', 'misc']:
                fullOutDir = os.path.join(sigDir, outDir)
                if not os.path.exists(fullOutDir):
                    os.makedirs(fullOutDir)
            
            zipUpdate = zipfile.ZipFile(io.BytesIO(response.read()))
            for zipFilePath in zipUpdate.namelist():
                sigName = os.path.basename(zipFilePath)
                if zipFilePath.endswith("/"):
                    continue
                # Skip incompatible rules
                skip = False
                for incompatible_rule in self.INCOMPATIBLE_RULES:
                    if sigName.endswith(incompatible_rule):
                        if logging == True:
                            self.logger.log("NOTICE", "Upgrader", "Skipping incompatible rule %s" % sigName)
                            do_remote_logging(self.remote_logger, "NOTICE", ["Upgrader", "Skipping incompatible rule %s" % sigName])
                        skip = True
                if skip:
                    continue
                # Extract the rules
                # self.logger.log("DEBUG", "Upgrader", "Extracting %s ..." % zipFilePath)
                if "/iocs/" in zipFilePath and zipFilePath.endswith(".txt"):
                    targetFile = os.path.join(sigDir, "iocs", sigName)
                elif "/yara/" in zipFilePath and zipFilePath.endswith(".yar"):
                    targetFile = os.path.join(sigDir, "yara", sigName)
                elif "/misc/" in zipFilePath and zipFilePath.endswith(".txt"):
                    targetFile = os.path.join(sigDir, "misc", sigName)
                elif zipFilePath.endswith(".yara"):
                    targetFile = os.path.join(sigDir, "yara", sigName)
                else:
                    continue

                # New file
                if not os.path.exists(targetFile):
                    self.logger.log("INFO", "Upgrader", "New signature file: %s saved" % sigName)
                    do_remote_logging(self.remote_logger, "INFO", ["Upgrader", "New signature file: %s saved" % sigName])
                # Extract file
                source = zipUpdate.open(zipFilePath)
                target = open(targetFile, "wb")
                with source, target:
                    shutil.copyfileobj(source, target)
                target.close()
                source.close()
        self.logger.log("INFO", "Upgrader", "Finished downloading latest signature files")        
        do_remote_logging(self.remote_logger, "INFO", ["Upgrader", "Finished downloading latest signature files"])
        
class LokiLogger:
    version = '0.45.0'
    FILE_LINE = 3
    SYSLOG_LINE = 4
    hostname = "NOTSET"
    alerts = 0
    messagecount = 0
    debug = False
    linesep = "\n"

    def __init__(self, log_file, hostname, platform, customformatter):
        self.log_file = log_file
        self.hostname = hostname
        self.CustomFormatter = customformatter
        if "windows" in platform.lower():
            self.linesep = "\r\n"

    def log(self, mes_type, module, message):
        # Counter
        if mes_type == "ALERT":
            self.alerts += 1
        self.messagecount += 1

        # to file
        if self.log_file:
            self.log_to_file(message, mes_type, module)
            
    def Format(self, type, message, *args):
        if not self.CustomFormatter:
            return message.format(*args)
        else:
            return self.CustomFormatter(type, message, args)
        
    def getSyslogTimestamp(self):
        date_obj = datetime.now()
        date_str = date_obj.strftime("%Y-%m-%d %H:%M:%S")
        return date_str    
    
    def log_to_file(self, message, mes_type, module):
        try:
            # Write to file
            with codecs.open(self.log_file, "a", encoding='utf-8') as logfile:
                logfile.write(self.Format(self.FILE_LINE, u"[{0}] {1} MALLEVEL: {2}: MODULE: {3} MESSAGE: {4}{5}", self.getSyslogTimestamp(), self.hostname, mes_type.title(), module, message, self.linesep))
        except Exception as e:
            print("Cannot print line to log file {0}".format(self.log_file))
         
                