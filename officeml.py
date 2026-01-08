# Run ONCE on startup to load PDF ML models into memory. Saves time un-pickling each time model is required for evaluation

import os	
import pickle
from constants import *
import subprocess
import re
from remote_logging import do_remote_logging
import warnings
import numpy, pandas
warnings.filterwarnings('ignore')

MODELS_IN_MEMORY =[]

def check_keyword(input_line, keywords):
    for keyword, v in keywords.items():
        k = keyword.replace('"', ' ').replace(',', ' ').strip().lower() 
        pattern1 = f'(?:\")?(\b{k}\b)(?:\s+)?'
        input_line = input_line.replace('.', '').replace(' ', '')
        match = re.search(pattern1, input_line, re.I)
        if match:
            return v
    for keyword, v in keywords.items():
        k = keyword.replace('"', ' ').replace(',', ' ').replace('.', '').strip().lower()
        pattern2 = f'(?:\")?({k})(?:\s+)?'
        input_line = input_line.replace('.', '').replace(' ', '')
        match = re.search(pattern2, input_line, re.I)
        if match:
            return v
    return 80

def word_feature_extraction(file_name, num_files=1 ):
    try:
        os.remove('./office_extraction_output.txt')
    except:
        pass
    try:
        subprocess.check_output('olevba -j  REPLACEME | grep -e "keyword" -e "sample" > ./office_extraction_output.txt'.replace("REPLACEME",file_name), shell=True)
    except:
        pass
    f = open('./office_extraction_output.txt', 'r+')
    lines = [line for line in f.readlines()]
    f.close()
    keywords = { ########### Top 20 ###########
                '"HexStrings",':0,'"Hex Strings",':0, '"Base64':1, '"Auto_Open",':2, '"AutoOpen",':2, 
                '"Shell",':3, '"Chr",':4, '"run",':5, '"showwindow",':6, '"Document_open",':7 ,
                '"CreateObject",':8, '"ChrW",':9,  '"vba_stomping",':10, '"Call",':11, 
                '"chrb",':12, '"vbhide",':13, '"Wscript.Shell",':14, '"stRrevErse",':15, '"Xor",':16, 
                '"dridex_strings",':17, '"open",':18, '"system",':19,
                ########### Benign ###########
                "_Click":20, "_Change":21, "VBA Stomping": 22, "sample":23, 
                "AutoExit":24, "Environ":25, "AutoExec":26, ".Variables":27, 
                "AutoNew":28, "Workbook_BeforeClose":29, "ActiveWorkbook.SaveAs":30,
                "command":31, "Document_New":32, "Application.Visible":33, "Workbook_Open":34,
                "AutoClose":35, "Document_Close":36, "vbNormal":37, "vbNormalFocus":38, 
                "GetObject":39, "windows":40, ".exe":41, "Lib":42,
                ############ Malicious ##########
                "Create":43, "REGISTER":44, "XLM macro":45, "Output":46, "Print #":47,
                "FileCopy":48, "FORMULA.FILL": 49, "EXEC":50, 
                "URLDownloadToFileA":51, "powershell":52,  "New-Object":53, 
                "Net.WebClient":54, "Sheet.ps1":55,"M:vB":56, ".'G":57, 
                "ADODB.Stream":58, "SaveToFile":59, "Microsoft.XMLHTTP":60,
                "ftr.cpl":61, "statis1c.dll":62,
                "ExpandEnvironmentStrings":63, "Workbook_Activate":64,
                "Write":65, "Put":66, "Binary":67,  "CopyHere":68, "Kill":69,
                "ExecuteExcel4Macro":70, "libOmio.dll":71, "http":72,
                "0azy":73, "Frame1_Layout":74, "CreateTextFile":75,
                "wscript.exe":76,  "powershell.exe":77, "msxml2.xmlhttp":78, "Virtual":79    
                }

    # Filling the Dataset
    dataset = numpy.zeros((num_files, len(keywords)))
    j=0
    for i in lines:
        if i.split(':')[0].strip()  == '"keyword"' :
            kwd = check_keyword(i.split(':')[1], keywords)
            dataset[j][kwd] = 1
        else:
            continue
    result = pandas.DataFrame(dataset)
    result.columns = list(keywords)
    dataset_ = result
    output = dataset[0][:-1]
    return output

for x in os.listdir(OFFICEML_MODEL_PATH):
    clf_pickle = open(OFFICEML_MODEL_PATH+'/'+x, 'rb')
    clf = pickle.load(clf_pickle)
    MODELS_IN_MEMORY.append(clf)

def predict_file(logger, remote_logger, file_path, file_name):
    features = word_feature_extraction(file_path)
    prediction_array=[]
    if not os.path.exists(file_path):
        logger.log("ERROR", "FilePredict", "Non-Existent File %s ... " % file_name)
        do_remote_logging(remote_logger, "ERROR", ["FilePredict", "Non-Existent File %s ... " % file_name])
        return {}
    logger.log("INFO", "FilePredict", "Extracting features from File %s ... " % file_name)
    do_remote_logging(remote_logger, "INFO", ["FilePredict", "Extracting features from File %s ... " % file_name])
    try:
        for model in MODELS_IN_MEMORY:
            result = model.predict([features])
            prediction_array.append(result[0])
        if 'Malicious' in prediction_array:
            return "DANGEROUS"
        else:
            return "SAFE"
    except Exception as e:
        logger.log("ERROR", "FilePredict", e)
        do_remote_logging(remote_logger, "ERROR", ["FilePredict", e])
        return {}   
    
