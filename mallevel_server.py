from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from flask_session import Session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from datetime import datetime as dt
from datetime import timedelta
from werkzeug.utils import secure_filename
from loki import *
from loki_objects import LokiLogger, LOKIUpdater
from general_functions import check_filename, platform_checker, hostname_checker, send_results_to_splunk,\
    get_signatures_info, generate_analysis_report, imports_json, initialize_signature_loggers,\
        connect_to_mongodb, get_compressed_files, scan_file, scan_compressed_files, get_message_type, \
            calculate_sha256, csv_to_html
import initialize_signatures
import functools
from fetch_malwarebazaar_signatures import fetch_malwarebazaar_hashes, process_malwarebazaar_hashes, fetch_malwarebazaar_code_signing_certificate_blocklist, process_malwarebazaar_code_signing_certificate_blocklist
from fetch_otx_signatures import OTXReceiver
from fetch_phishtank_urls import download_phishing_urls
from mongodb_crud import *
from splunk_logger import SplunkLogger
from remote_logging import do_remote_logging
from constants import *
import os
import json
from flask_cors import CORS, cross_origin
from urlml import predictURL, url_blacklist_lookup

# APPLICATION CONFIGURATION
app = Flask(__name__)

CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)
app.permanent_session_lifetime = timedelta(minutes=30)

app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000 * 1000 # restrict maximum file size of uploads
app.config['UPLOAD_FOLDER'] = UPLOAD_PATH # to store uploaded files, either by UI or by agent

app.config["SESSION_TYPE"] = "filesystem"
Session(app) # session to store analysis results, for on-demand scanning via UI
app.secret_key = os.urandom(24) # sample secret key

init_logger, init_remote_logger = initialize_signature_loggers() # to initialize logger for logging initialization of signatures

# Number System for checking whether endpoint is in sync with server's defined configurations
# e.g. initially, server's dcount (<-> directories monitored), 
# wcount (<-> whitelist hashes) and mcount (<-> monitoring interval) will be all 0s.
# when any of the above 3 items are updated, increment respective count by 1
# so that when endpoint probes server for existing configuration, it will not fetch the 
# whole list/dictionary of large information if server counts are 0 and endpoint counts are also 0 (matching)
# it will only fetch necessary information when endpoint count is different from server count
server_counts = {"dcount": 0, "mcount": 0, "wcount": 0}

@login_manager.user_loader
def load_user(username):
    user = get_user_mongodb(username)
    return user

# Customize login_required decorator to redirect users to their destination page
def login_required(func):
    @functools.wraps(func)
    def secure_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login", next=request.url))
        return func(*args, **kwargs)
    return secure_function

# Admin_required decorator to allow admins access to certain administrative functions
def admin_required(func): # Checks if current user has admin privilege. If yes, then able to access admin functions like dashboard, whitelisting, signature updates, etc.
    @functools.wraps(func)
    def check_admin(*args, **kwargs):     
        if current_user.is_admin() == False:
            return render_template("error401.html")
        return func(*args, **kwargs)
    return check_admin

# Login page for authenticated users to access restricted views, e.g. signature updates, dashboard, whitelisting
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        logout_user()
        session.pop("username", None)
    except:
        pass
    session.pop("username", None)
    message = session.pop("message", None)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        next_url = request.form.get("next")
        user = validate_user_mongodb(username, password)
        if user == None:
            error = "Incorrect credentials."
            return render_template("login.html", error = error)
        else:
            login_user(user)
            session["username"] = username # important; keeps user logged in for user_loader callback
            if next_url:
                return redirect(next_url)
            return redirect(url_for("upload_file"))
    return render_template("login.html", message = message)

# Admin logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("username", None)
    return redirect(url_for("upload_file"))

# Allows admin to change the default password
@app.route('/changepassword', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == "POST":
        current_user
        current_password = request.form.get("current")
        new_password = request.form.get("new1")
        confirm_new_password = request.form.get("new2")
        validated = validate_user_mongodb(current_user.username, current_password)
        if (new_password == current_password and validated != None) or (confirm_new_password == current_password and validated != None):
            error = "Please set a password that is different from your current one."
            return render_template("changepassword.html", error = error)
        elif new_password == confirm_new_password and validated != None:
            updated = update_password_mongodb(current_user.username, new_password)
            if updated:
                message = "Your password has been successfully changed."
                session["message"] = message
                logout_user()
                session.pop("username", None)
                return redirect(url_for("login"))
        error = 'Incorrect credentials.'
        return render_template("changepassword.html", error = error)
    return render_template("changepassword.html")

# ROUTE FOR USERS TO GENERATE NEW API KEY (TO BE USED IN AGENT CONFIGURATION FILE)
@app.route('/requestapikey', methods=['GET', 'POST'])
@login_required
def request_api_key():
    if request.method == "POST":
        api_key_generated = generate_api_key_mongodb(current_user.username)
        if api_key_generated == False:
            error = "You are only allowed to generate a new API key once a day."
            return render_template("requestapikey.html", error = error)
        return redirect(url_for("request_api_key"))
    return render_template("requestapikey.html")

# DEFAULT APP ROUTE; ALLOWS USER TO UPLOAD FILE/S AS PART OF MANUAL SCANNING (WEB UI)
@app.route('/')
@app.route('/uploadfile', methods=['GET', 'POST'])
def upload_file():
    error = None
    if "scan" not in session:
        session["scan"] = None
    if "analysis_report" not in session:
        session["analysis_result"] = None
    if "analysis_stats" not in session:
        session["analysis_stats"] = None
    # MALLEVEL offers 2 modes of submission (1. On-demand using Web UI. 2. Background submission via MALLEVEL agent)
    # Default submission would be on-demand (background = False)
    if request.method == 'POST':
        upload_files = request.files.getlist('File') # Request that identifies user-initiated uploads; hence no change to session['background']
        upload_files_path = {}
        for upload_file in upload_files:
            # if allowed_file(upload_file.filename): # comment/uncomment depending on use case; whether uploaded files should be restricted based on their types
            original_file = upload_file
            new_filename = secure_filename(upload_file.filename)
            # secure_filename may return "not eicar.txt" as "not_eicar.txt"
            # if files "not eicar.txt" and "not_eicar.txt" are submitted, final result is only 1 file
            # hence need to add unique value if such a case arises
            unique_filename = check_filename(new_filename, original_file, upload_files.copy())
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            if os.path.exists(filepath):
                os.remove(filepath)
            upload_file.save(filepath)
            upload_files_path[original_file.filename] = filepath
            upload_file.close()
        session['scan'] = upload_files_path
        session['analysis_report'] = None
        return redirect(url_for('loading')) # Redirects users to loading page (as part of UX) while waiting for scan to complete
    return render_template("uploadfile.html", error = error)

# API ENDPOINT FOR SERVER TO PASS CONFIGURATIONS TO ENDPOINTS VIA AGENT (E.G. CONSISTENTLY MONITOR ALL ENDPOINTS' DOWNLOADS DIRECTORY)
@app.route('/api/endpointconfig', methods=['POST'])
def endpoint_config():
    if request.method == "POST":
        client_api_key = request.headers.get("Authorization")
        client_hostname = request.form["hostname"]
        client_username = request.form["username"]
        client_ip = request.form["ip"]
        client_api_key_status = check_api_key_mongodb(client_api_key, client_hostname, client_username) # Each API key should only be used by a single host (and hence single user). No sharing of API keys across devices and users.
        print("Received connection request from %s (%s - %s)" % (client_ip, client_hostname, client_username))
        if client_api_key_status == "Needs Update": # This means client API key is valid too, just that need to auto-update few details (e.g. computer username, computer hostname)
            update_api_key_details_mongodb(client_api_key, client_hostname, client_username, client_ip)
        elif client_api_key_status == None:
            print("The connection request from %s (%s - %s) is unauthenticated." % (client_ip, client_hostname, client_username))
            return {}, 401 # return empty content and unauthorized error code
        
        # Below codes apply for validated client API keys
        print("The connection request from %s (%s - %s) has been authenticated." % (client_ip, client_hostname, client_username))
        configurations = {}
        try:
            client_dcount = int(request.form["dcount"])
            client_mcount = int(request.form["mcount"])
            client_wcount = int(request.form["wcount"])
        except:
            client_dcount, client_mcount, client_wcount = 0, 0, 0
        if client_dcount != server_counts["dcount"]:
            configurations['monitor_directory'] = get_directory_mongodb()
        if client_mcount != server_counts["mcount"]:
            configurations['monitor_interval'] = get_monitor_interval_mongodb()
        if client_wcount != server_counts["wcount"]:
            configurations['whitelisted_hashes'] = get_whitelist_hashes_mongodb()
        configurations["dcount"] = server_counts["dcount"]
        configurations["mcount"] = server_counts["mcount"]
        configurations["wcount"] = server_counts["wcount"]
        return configurations, 200
    
# API endpoint for uploading files; separate from web UI uploads
@app.route('/api/uploadfile', methods=['POST'])
def api_upload_file():
    if "scan" not in session:
        session["scan"] = None
    if "background" not in session:
        session["background"] = True
    if request.method == 'POST':
        client_api_key = request.headers.get("Authorization")
        client_hostname = request.form["hostname"]
        client_username = request.form["username"]
        client_filepaths = json.loads(request.form["filepaths"])
        client_ip = request.form["ip"]
        client_api_key_status = check_api_key_mongodb(client_api_key, client_hostname, client_username)
        if client_api_key_status == "Needs Update": # This means client API key is valid too, just that need to auto-update few details
            update_api_key_details_mongodb(client_api_key, client_hostname, client_username, client_ip)
        elif client_api_key_status == None:
            print("The file submission request from %s (%s - %s) is unauthenticated." % (client_ip, client_hostname, client_username))
            return {}, 401 # return empty content and unauthorized error code
        print("The file submission request from %s (%s - %s) has been authenticated." % (client_ip, client_hostname, client_username))
        upload_files = request.files.getlist('file') # Request that identifies user-initiated uploads; hence no change to session['background']
        upload_files_path = {}
        for upload_file in upload_files:
            # if allowed_file(upload_file.filename): # comment/uncomment depending on use case; whether uploaded files should be restricted based on their types
            original_file = upload_file
            new_filename = secure_filename(upload_file.filename)
            unique_filename = check_filename(new_filename, original_file, upload_files.copy())
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            if os.path.exists(filepath):
                os.remove(filepath)
            upload_file.save(filepath)
            upload_files_path[original_file.filename] = filepath
            upload_file.close()
        session['scan'] = upload_files_path
        scan_report = scan() # If background submission, straightaway invoke the scan function and return the report (as dictionary)
        try:
            malicious_files = scan_report["statistics"]["malicious_files"]
            # malicious_files = ["eicar.com.txt"] # hardcoded for testing functionality
            for malicious_file in malicious_files:
                original_file_path = os.path.join(UPLOAD_PATH, scan_report["files"][malicious_file]["secured_file_name"])
                if os.path.exists(original_file_path):
                    sha256_hash = scan_report["files"][malicious_file]["sha256"]
                    for path, name in client_filepaths.items():
                        if name == malicious_file:
                            client_filepath = path
                            break
                    add_quarantine_mongodb(sha256_hash, malicious_file, client_filepath, client_hostname, client_username)
            session.pop('analysis_report', None) # For API submission, no need to retain the analysis report (unlike web UI)
        except:
            pass
        print("Sending MALLEVEL Scan Report to MALLEVEL Agent at IP: " + client_ip)
        return scan_report, 200
    return {}, 401

# API endpoint for checking file quarantine status; so that endpoint can release files if safe
@app.route('/api/quarantinestatus', methods=['POST'])
def api_quarantine_status():
    if request.method == 'POST':
        client_api_key = request.headers.get("Authorization")
        client_hostname = request.form["hostname"]
        client_username = request.form["username"]
        client_ip = request.form["ip"]
        client_quarantined_files = json.loads(request.form["files_in_quarantine"])
        client_api_key_status = check_api_key_mongodb(client_api_key, client_hostname, client_username)
        if client_api_key_status == "Needs Update": # This means client API key is valid too, just that need to auto-update few details
            update_api_key_details_mongodb(client_api_key, client_hostname, client_username, client_ip)
        elif client_api_key_status == None:
            print("The quarantine query request from %s (%s - %s) is unauthenticated." % (client_ip, client_hostname, client_username))
            return {}, 401 # return empty content and unauthorized error code
        print("The quarantine query request from %s (%s - %s) has been authenticated." % (client_ip, client_hostname, client_username))
        files_status = get_user_files_to_release_and_delete_mongodb(client_hostname, client_username, client_quarantined_files)
        return files_status, 200
    return {}, 401

@app.route('/api/phishcheck/<url>/', methods=['GET','POST','OPTIONS'])
@cross_origin()
def checkurl(url):
    found, reason = url_blacklist_lookup(url, initialize_signatures.INITIALIZED_BLACKLISTED_URLS)
    if found: # Found means found in list of blacklisted URLs
        result = 'Danger'
        print('Danger:', reason)
    else:
        result = 'Benign'
    if ' Benign' not in predictURL(url):
        print('!!!!!')
        result = 'Danger'
    try:
        print(json.dumps({'Response':result}))
        return json.dumps({'Response':result})
    except:
        return json.dumps({'Response':'Benign'})

# VIEW ANALYSIS RESULTS ON WEB UI AFTER SCANNING BY SIGNATURE-BASED DETECTION AND ML PREDICTION
@app.route('/viewresults')
def view_results():
    error = None
    if session.get("scan") == None:
        error = "No Scan"
        return render_template('results.html', analysis_report = None, error = error)
    else:
        if session.get("analysis_report") == None:
            error = "No Results"
            return render_template('results.html', analysis_report = None, error = error)
        else:
            analysis_report = session.get("analysis_report")
            return render_template('results.html', analysis_report = analysis_report)

# FUNCTION RESPONSIBLE FOR SIGNATURE-BASED DETECTION AND ML PREDICTION
@app.route('/scan')
def scan():
    if session.get("scan") == None:
        return redirect(url_for(view_results))
    else:
        if session.get("analysis_report") == None:
            analysis_result = {}
            analysis_stats = []
            date_obj = dt.now()
            date_str = date_obj.strftime("%Y-%m-%d-%H-%M-%S")
            analysis_log_name = "mallevel-analysis-log-%s.log" % date_str
            analysis_log_path = os.path.join(ANALYSIS_LOG_PATH, analysis_log_name)
            platform = platform_checker()
            hostname = hostname_checker(platform)
            logger = LokiLogger(analysis_log_path, hostname, platform, None)
            connect_mongodb = connect_to_mongodb(MONGODB_HOST, MONGODB_PORT) # Reinitiate the connection to MongoDB for every scan, in case it went down while the MALLEVEL server is still up
            try:
                remote_logger = SplunkLogger(hostname, sourcetype = "mallevel_analysis_logs", token = SPLUNK_ANALYSIS_LOGS_TOKEN) # Only send logs to Splunk instance if alive; hence many tries and excepts to handle failed Splunk connections...
                remote_logger.notice(["Init", "The MALLEVEL Server will also be sending logs to the Splunk instance at %s:%s" % (SPLUNK_HOST, SPLUNK_PORT)])
                logger.log("NOTICE", "Init", "The MALLEVEL Server will also be sending logs to the Splunk instance at %s:%s" % (SPLUNK_HOST, SPLUNK_PORT))
            except:
                remote_logger = None
                logger.log("ERROR", "Init", "The MALLEVEL Server is unable to connect to the Splunk instance at %s:%s" % (SPLUNK_HOST, SPLUNK_PORT))
                pass
            if connect_mongodb == None:
                logger.log("ERROR", "Init", "The MALLEVEL Server is unable to connect to the MALLEVEL Database at %s:%s" % (MONGODB_HOST, MONGODB_PORT))
                do_remote_logging(remote_logger, "ERROR", ["Init", "The MALLEVEL Server is unable to connect to the MALLEVEL Database at %s:%s" % (MONGODB_HOST, MONGODB_PORT)])
            else:
                logger.log("NOTICE", "Init", "The MALLEVEL Server is connected to the MALLEVEL Database at %s:%s" % (MONGODB_HOST, MONGODB_PORT))
                do_remote_logging(remote_logger, "NOTICE", ["Init", "The MALLEVEL Server is connected to the MALLEVEL Database at %s:%s" % (MONGODB_HOST, MONGODB_PORT)])
            intense_scanner = Loki(logger = logger, remote_logger = remote_logger, intense_mode = True, os_platform = platform, signatures = initialize_signatures.INITIALIZED_SIGNATURES)
            analysis_start_time = dt.now().strftime("%d %B %Y %H:%M:%S")
            file_paths = session.get("scan")
            for original_filename, file_path in file_paths.items():
                file_name, file_type, file_result, pe_heuristics_result, prediction_result = scan_file(logger, remote_logger, intense_scanner, file_path, original_filename, connect_mongodb) # Main scan function that will invoke Loki Detection and ML Prediction
                analysis_result[file_name] = file_result
                analysis_result[file_name]["prediction"] = prediction_result
                analysis_result[file_name]["heuristics"] = pe_heuristics_result
                if file_type in SUPPORTED_ZIP_EXTRACTION_TYPES: # If file is confirmed to be zip (based on file type signature), perform one-time extraction (even for nested zip files) to get a list of all contained files
                    compressed_file_paths = get_compressed_files(logger, remote_logger, file_path, file_name) # Get a list of all files compressed within the zip file
                    compressed_file_results, zip_total_score, zip_reasons, compressed_file_name_list = scan_compressed_files(logger, remote_logger, intense_scanner, compressed_file_paths, connect_mongodb) # Scan all compressed files
                    analysis_result.update(compressed_file_results) 
                    analysis_result[file_name]["contains"] = compressed_file_name_list # list of files contained within the zip file
                    analysis_result[file_name]["signature_detection_score"] = zip_total_score # total score of all files contained within the zip file
                    analysis_result[file_name]["reasons"] = zip_reasons # reasons for the total score
                    analysis_result[file_name]["verdict"] = get_message_type(zip_total_score)
            analysis_file_count = len(file_paths)
            analysis_end_time = dt.now().strftime("%d %B %Y %H:%M:%S")
            analysis_stats = [analysis_start_time, analysis_end_time, analysis_file_count]
            analysis_report, analysis_results, analysis_classification = generate_analysis_report(analysis_result, analysis_stats, connect_mongodb, session.get("agent_username", None), session.get("agent_hostname", None))
            logger.log("INFO", "Results", "RESULTS: %d Dangerous Files, %d Safe Files" % (analysis_classification[0], analysis_classification[1]))
            do_remote_logging(remote_logger, "INFO", ["Results", "RESULTS: %d Dangerous Files, %d Safe Files" % (analysis_classification[0], analysis_classification[1])])
            session['analysis_report'] = analysis_report
            analysis_report_name = "mallevel-analysis-report-%s.json" % date_str
            session['analysis_report_name'] = analysis_report_name
            analysis_report_path = os.path.join(ANALYSIS_REPORT_PATH, analysis_report_name)
            with open(analysis_report_path, "w") as write_file:
                json.dump(analysis_report, write_file, indent=4)
            try:
                remote_logger_2 = SplunkLogger(hostname, sourcetype = "mallevel_results_logs", token = SPLUNK_RESULTS_LOGS_TOKEN) # Only send logs to Splunk instance if alive
                send_results_to_splunk(analysis_results, remote_logger_2)
            except:
                pass
            if session.get("background") == True: # Check current state of submission; True = background submission
                return analysis_report # Return the report dictionary to uploadfile function, invoked by MALLEVEL agent, instead of redirecting to Web UI. Also return list of malicious file names for agent to perform quarantine
        else:
            return redirect(url_for(view_results))
        return "Scan Done"

# LOADING PAGE WHILE WAITING FOR SCAN TO COMPLETE
@app.route('/loading')
def loading():
    return render_template('loading.html')        

# VIEW LOKI SIGNATURE FILES STORED IN SIGNATURE DIRECTORY   
@app.route('/viewsignature')
@login_required
@admin_required
def view_signature():
    iocs_file_info = get_signatures_info(IOCS_DIR_PATH)
    misc_file_info = get_signatures_info(MISC_DIR_PATH)
    yara_file_info = get_signatures_info(YARA_DIR_PATH)
    return render_template("viewsignature.html", iocs_file_list = iocs_file_info, misc_file_list = misc_file_info, yara_file_list = yara_file_info)

# UPDATE LOKI SIGNATURE FILES BY FETCHING SIGNATURES FROM LOKI ARCHIVE (ZIP)
# ADDED EXTERNAL SIGNATURE SOURCES LIKE MALWAREBAZAAR AND ALIENVAULT OTX
@app.route('/updatesignature', methods=['GET', 'POST'])
@login_required
@admin_required
def update_signature():
    logs = None
    if "logs" not in session:
        session["logs"] = None
    else:
        logs = session.get(logs)
    if request.method == 'POST':
        platform = platform_checker()
        hostname = hostname_checker(platform)
        # Logger
        date_obj = dt.now()
        date_str = date_obj.strftime("%Y-%m-%d-%H-%M-%S")
        update_log_name = "mallevel-update-log-%s.log" % date_str
        update_log_path = os.path.join(UPDATE_LOG_PATH, update_log_name)
        logger = LokiLogger(update_log_path, hostname, platform, None)
        try: 
            remote_logger = SplunkLogger(hostname, sourcetype = "mallevel_update_logs", token = SPLUNK_UPDATE_LOGS_TOKEN) # Only send logs to Splunk instance if alive
        except:
            pass
        updater = LOKIUpdater(logger, remote_logger, MALLEVEL_PATH)
        updater.update_signatures(clean=False)
        
        # Below codes are for updating signatures and/or URLs (from external sources, e.g. MalwareBazaar, Alienvault OTX, PhishTank)
        if UPDATE_EXTERNAL_SIGNATURES == True:
            malwarebazaar_hash_updater = fetch_malwarebazaar_hashes(logger, remote_logger) # Since MalwareBazaar hashes come in a single zip file, we are unable to perform incremental updates
            if malwarebazaar_hash_updater:
                process_malwarebazaar_hashes(logger, remote_logger)
            try:
                malwarebazaar_certificate_blocklist_updater = fetch_malwarebazaar_code_signing_certificate_blocklist(logger, remote_logger)
                if malwarebazaar_certificate_blocklist_updater:
                    process_malwarebazaar_code_signing_certificate_blocklist(logger, remote_logger)
            except:
                pass       
            try:
                otx_receiver = OTXReceiver(logger, remote_logger, OTX_API_KEY) # However for OTX API, we can filter recent events (and hence add recent IOCs to our existing signature files)
                otx_receiver.get_iocs()
                otx_receiver.write_iocs()
            except: 
                pass
            try:
                download_phishing_urls(logger, remote_logger) # Download Phishing URLs from PhishTabk
            except:
                pass
        
        with open(update_log_path, "r") as logfile:
            logs = []
            for line in logfile:
                logs.append(line.strip())
        session["logs"] = logs
        # Everytime the signatures are updated, reinitialize signatures so that the next scan uses the updated signatures
        update_logger, update_remote_logger = initialize_signature_loggers()
        initialize_signatures.INITIALIZED_SIGNATURES, initialize_signatures.INITIALIZED_BLACKLISTED_URLS = initialize_signatures.initialize_all_signatures(update_logger, update_remote_logger)
    return render_template('updatesignature.html', logs = session["logs"])

# ALLOWS USERS TO DOWNLOAD JSON REPORTS AFTER VIEWING THE ANALYSIS RESULTS IN THE WEB UI
@app.route('/downloadreport')
def download_report():
    if "analysis_report_name" not in session:
        return render_template('error404.html'), 404
    else:
        analysis_report_name = session.get("analysis_report_name")
        return send_from_directory(ANALYSIS_REPORT_PATH, analysis_report_name, as_attachment=True)

# ADMIN INTERFACE FOR CREATING NEW USERS (FOR WEB UI)
@app.route('/createuser', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == "POST":
        username = request.form["username"]
        created = create_user_mongodb(username)
        if created == False:
            error = "The username %s has already been taken." % username
            return render_template("createuser.html", error = error)
        elif created == True:
            message = "The user %s has been successfully created." % username
            return render_template("createuser.html", message = message)
    return render_template("createuser.html")

# ADMIN INTERFACE FOR VIEWING EXISTING USER ACCOUNTS (FOR WEB UI)
@app.route('/viewusers', methods=['GET', 'POST'])
@login_required
@admin_required
def view_users():
    users_info = get_all_user_details_mongodb()
    return render_template("viewusers.html", users_info = users_info)

# ADMIN INTERFACE FOR DELETING USER ACCOUNTS
@app.route('/deleteuser/<username>', methods=['POST'])
@login_required
@admin_required
def delete_user(username):
    if request.method == "POST":
        delete_user_mongodb(username)
    return redirect(url_for("view_users"))

# ADMIN INTERFACE FOR WHITELISTING CERTAIN FILE HASHES (WILL BE RECORDED TO DATABASE)
@app.route('/whitelistfile', methods=['GET', 'POST'])
@login_required
@admin_required
def whitelist_file():
    if request.method == 'POST':
        whitelist_files = request.files.getlist('File') # Request that identifies files to be whitelisted by admin     
        whitelist_files_dict = {}
        for whitelist_file in whitelist_files:
            file_path = os.path.join(WHITELIST_PATH, whitelist_file.filename)
            whitelist_file.save(file_path)
            whitelist_file.close()
            sha256_hash = calculate_sha256(file_path)
            whitelist_files_dict[sha256_hash] = whitelist_file.filename
        new_hashes, existed_hashes = add_whitelist_hashes_mongodb(whitelist_files_dict)
        if new_hashes == None and existed_hashes == None:
            error = "The MongoDB Database is currently not running..."
            return render_template('whitelistfile.html', error = error)
        else:
            server_counts["wcount"] += 1
            return render_template('whitelistfile.html', new_hashes = new_hashes, existed_hashes = existed_hashes)
    return render_template('whitelistfile.html')

# ADMIN INTERFACE FOR VIEWING WHITELISTED FILES (IN DATABASE)
@app.route('/viewwhitelistedfiles', methods=['GET'])
@login_required
@admin_required
def view_whitelisted_files():
    whitelist_files_dict = get_whitelisted_files_mongodb()
    return render_template('viewwhitelistedfiles.html', whitelist_files_dict = whitelist_files_dict)

# DELETE DIRECTORY TO MONITOR IN ENDPOINTS
@app.route('/deletewhitelisthash/<hash>', methods=['POST'])
@login_required
@admin_required
def delete_whitelist_hash(hash):
    if request.method == "POST":
        delete_whitelist_hash_mongodb(hash)
        server_counts["wcount"] += 1
    return redirect(url_for("view_whitelisted_files"))

# ADMIN INTERFACE FOR VIEWING DASHBOARD OF INFORMATION STORED IN MONGODB DATABASE
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
@admin_required
def dashboard():
    unique_files_scanned, unique_files_ml, file_verdicts, file_types = fetch_mongodb_dashboard()
    if unique_files_scanned == None:
        error = "The dashboard cannot be displayed as MongoDB is currently down."
        return render_template("dashboard.html", error = error, no_of_unique_files_scanned = None)
    return render_template("dashboard.html", no_of_unique_files_scanned = unique_files_scanned,\
        no_of_unique_files_ml = unique_files_ml, file_verdicts = file_verdicts,\
            file_types = file_types)
    
# ADMIN INTERFACE FOR VIEWING CONFIGURATIONS (BOTH SERVER AND ENDPOINT) STORED IN MONGODB DATABASE
@app.route('/viewconfigurations', methods=['GET'])
@login_required
@admin_required
def view_configurations():
    monitored_directories = get_directory_mongodb()
    monitor_interval = get_monitor_interval_mongodb()
    return render_template("viewconfigurations.html", monitored_directories = monitored_directories, monitor_interval = monitor_interval)
 
# ADMIN INTERFACE FOR VIEWING QUARANTINED FILES STORED IN MONGODB DATABASE
@app.route('/viewquarantinedfiles_admin', methods=['GET'])
@login_required
@admin_required
def view_quarantined_files_admin():
    quarantined_files = get_quarantine_mongodb()
    return render_template("viewquarantinedfiles_admin.html", quarantined_files = quarantined_files)
 
# USER INTERFACE FOR VIEWING SELF-SUBMITTED FILES THAT GOT QUARANTINED
@app.route('/viewquarantinedfiles_user', methods=['GET'])
@login_required
def view_quarantined_files_user():
    quarantined_files = get_user_quarantine_mongodb(current_user.username)
    if quarantined_files == False:
        message = "You have not created an API key and have not started using the MALLEVEL agent.<br>Hence you do not have any quarantined files.<br><a href='/requestapikey'>Generate an API Key.</a>"
        return render_template("viewquarantinedfiles_user.html", message = message)   
    return render_template("viewquarantinedfiles_user.html", quarantined_files = quarantined_files)   
    
# USER INTERFACE FOR REQUESTING ADMINISTRATOR TO ANALYZE QUARANTINED FILES
@app.route('/requestfileanalysis/<file_hash>/<web_username>', methods=['POST'])
@login_required
def request_file_analysis(file_hash, web_username):
    if request.method == "POST":
        requested = request_file_analysis_mongodb(file_hash, web_username)
        return redirect(url_for("view_quarantined_files_user"))
    return render_template("viewquarantinedfiles_user.html")       
    
# ADD DIRECTORY TO MONITOR IN ENDPOINTS (AGENT WILL MONITOR DOWNLOADS BY DEFAULT IF NO DIRECTORY IS CONFIGURED ON SERVER)  
@app.route('/add_directory', methods=['POST'])
@login_required
@admin_required
def add_directory():
    if request.method == "POST":
        directory = request.form['directory']
        if directory != "":
            add_directory_mongodb(directory)
            server_counts["dcount"] += 1
    return redirect(url_for("view_configurations"))

# DELETE DIRECTORY TO MONITOR IN ENDPOINTS
@app.route('/delete_directory/<directory>', methods=['POST'])
@login_required
@admin_required
def delete_directory(directory):
    if request.method == "POST":
        delete_directory_mongodb(directory)
        server_counts["dcount"] += 1
    return redirect(url_for("view_configurations"))

# CHANGE QUARANTINE STATUS OF SPECIFIED FILE
@app.route('/change_quarantine_status/<file_hash>/<hostname>/<username>/<new_status>', methods=['POST'])
@login_required
@admin_required
def change_quarantine_status(file_hash, hostname, username, new_status):
    if request.method == "POST":
        change_quarantine_status_mongodb(file_hash, hostname, username, new_status)
    return redirect(url_for("view_quarantined_files_admin"))

# CHANGE TIME INTERVAL AT WHICH THE DIRECTORY ON ENDPOINTS ARE BEING MONITORED
@app.route('/change_interval/<old_interval>', methods=['POST'])
@login_required
@admin_required
def change_interval(old_interval):
    if request.method == "POST":
        new_interval = request.form['interval']
        if old_interval != new_interval:
            change_monitor_interval_mongodb(old_interval, new_interval)
            server_counts["mcount"] += 1
    return redirect(url_for("view_configurations"))

# VIEW MALLEVEL WORKFLOW
@app.route('/workflow')
def work_flow():
    return render_template("mallevelworkflow.html")

# VIEW MALLEVEL SAMPLE RESULTS
@app.route('/resultshtml')
def results_html():
    return render_template("mallevelresultshtml.html")

# VIEW MALLEVEL SPLUNK INTEGRATION INFORMATION
@app.route('/splunk')
def splunk():
    return render_template("mallevelsplunk.html")

# VIEW ML INFO FOR PE
@app.route('/pe')
def pe():
    pe_dataset = csv_to_html(MDML_DATASET_PATH, "PE")
    return render_template("mallevelpe.html", pe_dataset = pe_dataset)

# VIEW ML INFO FOR PDF
@app.route('/pdf')
def pdf():
    return render_template("mallevelpdf.html")

# VIEW ML INFO FOR OFFICE DOCUMENTS
@app.route('/office')
def office():
    office_dataset = csv_to_html(OFFICEML_DATASET_PATH, "OFFICE")
    return render_template("malleveloffice.html", office_dataset = office_dataset)

# VIEW ML INFO FOR URLS
@app.route('/url')
def url():
    url_dataset = csv_to_html(URLML_DATASET_PATH, "URL")
    return render_template("mallevelurl.html", url_dataset = url_dataset)


# ERROR HANDLERS
@app.errorhandler(401)
def unauth(e):
    return render_template('error401.html'), 401

@app.errorhandler(404)
def notfound(e):
    return render_template('error404.html'), 404

@app.errorhandler(405)
def unauth(e):
    return render_template('error405.html'), 405

@app.errorhandler(413)
def large(e):
    return render_template('error413.html'), 413

@app.errorhandler(500)
def notfound(e):
    return render_template('error500.html'), 500

if __name__ == '__main__':
    context = ('server.crt', 'key1.key')
    app.run(threaded = True, debug = False, host = "0.0.0.0", ssl_context = context)

