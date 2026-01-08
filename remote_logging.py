def do_remote_logging(remote_logger, classification, message):
    try:
        if classification == "SAFE":
            remote_logger.safe(message)
        elif classification == "DANGEROUS":
            remote_logger.dangerous(message)
        elif classification == "ERROR":
            remote_logger.error(message)
        elif classification == "INFO":
            remote_logger.info(message)
        elif classification == "DEBUG":
            remote_logger.debug(message)    
        elif classification == "RESULTS":
            remote_logger.results(message)    
        else:
            remote_logger.warning(message)
        
    except:
        pass