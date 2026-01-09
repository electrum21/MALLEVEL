# MALLEVEL
MALLEVEL is an integrated anti-malware agent-server solution developed to provide enhanced security for Windows endpoints using a combination of signature-based detection and machine-learning analysis, based off the repositories [Loki](https://github.com/Neo23x0/Loki) and MDML (no longer available).

### Project Objective
The primary goal of this project was to research and develop an open-source security solution capable of detecting malicious Portable Executables (PEs), PDFs, and Office Documents through both traditional indicators of compromise (IOCs) and advanced machine-learning models.


### Core Features
**Agent-Server Architecture:**  
Features a Python-based agent that monitors endpoint directories and automatically uploads new files to a centralized Flask-based server for scanning, which can be deployed in an enterprise environment.  

**Centralized Management Web UI:**  
A user-friendly web interface for administrators to monitor scan results, manage user authentication, and update malware signatures.  

**Advanced File Handling:**  
Support for automated extraction and scanning of compressed archives (e.g., .zip, .7z, .gz).  

**Hybrid Detection Engine:**  
Combines signature-based scanning (utilizing ~710,000 IOCs from platforms like MalwareBazaar and AlienVault) with an integrated XGBoost machine-learning model for predicting zero-day threats.  

**Incident Response Tools:**  
Includes a built-in file quarantine system allowing for the isolation, restoration, or permanent deletion of detected threats.  

**Real-time Analytics:**  
Allows for integration with Splunk via HTTP Event Collector (HEC) for live event analysis and visual dashboards of scanning operations.  

### System Architecture
**Agent:** Runs as a Windows service, monitors local directories, and communicates with the server via authenticated API keys.  
**Server:** Receives files, performs signature/heuristic/ML analysis, and logs results to MongoDB and Splunk.  
**Heuristics:** Performs static analysis (e.g., entropy checks and anti-debugging detection) to identify suspicious file properties.  

For a detailed report of the project, from ideation to the final product, refer [here](https://github.com/electrum21/MALLEVEL/blob/main/mallevel_readme.md)  
If you would like to try out this project, click [here](https://mallevel-minimalised.onrender.com/) (Compact Version of Original Project)
