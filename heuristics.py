import os
import peutils
import pefile
from constants import MISC_DIR_PATH, UPLOAD_PATH
from remote_logging import do_remote_logging


PEID_RULES_PATH = os.path.join(MISC_DIR_PATH, 'peid-rules.txt')
VERBOSE = True

# Known Good Entry Point Sections
good_entry_point_sections = ['.text', '.code', 'CODE', 'INIT', 'PAGE']


# NtQueryInformationProcess is used to return various information about a specified process. This function is sometimes used as an anti-debugging technique because it can return the same information as CheckRemoteDebuggerPresent.
# NtSetInformationThread can be used to hide a thread from a debugger. 
# IsDebuggerPresent allows an application to determine whether or not it is being debugged, so that it can modify its behavior.
# CheckRemoteDebuggerPresent checks if a debugger (in a different process on the same machine) is attached to the current process.
# FindWindow checks for the presence of known windows from debuggers and forensic tools; various malware will behave differently if it finds the window, it might exit, or will try to close the window, etc...
# GetWindowThreadProcessId can be used searching the window for the ID of the parent process; if the parent process looks like a debugger, the owning thread  can be suspended using SuspendThread or NtSuspendThread.
# Process32First/Process32Next is used to begin enumerating processes from a previous call to CreateToolhelp32Snapshot; malware often enumerates through processes to find a process into which to inject.
anti_debug_imports = ['NtQueryInformationProcess', 'NtSetInformationThread', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'FindWindow', 'GetWindowThreadProcessId', 'Process32First', 'Process32Next']


# The Characteristics field contain information about the contents and memory protections associated with the section 
# when it is mapped into memory. In most cases, these flags are constant between executables and deviation from such
# standard values will almost surely trigger a generic detection of some sort.
characteristics_check_sections = { 
    ".text": "0x60000020",              
    ".rdata": "0x40000040",            
    '.data': "0xc0000040",
    '.rsrc': "0x40000040",
    '.reloc': "0x42000040"
}


# To load all PEID Signatures (of Packers)
sigs = peutils.SignatureDatabase(PEID_RULES_PATH)

# Check if file uses any anti-debugging techniques
def check_antidbg(pe):
    if VERBOSE:
        print("\nCHECKING FOR ANTI-DEBUGGING TECHNIQUES:")
    has_antidbg = False
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports: # Check if any of the imports are imports for anti-debugging technique
                if imp.name != None and imp.name != "":
                    imp_name = imp.name.decode('utf-8')
                    for i in anti_debug_imports: 
                        if(imp_name.startswith(i)):
                            print("  %s    |    %s  [SUSPICIOUS]" % (imp_name, i))
                            has_antidbg = True
    except:
        if VERBOSE:
            print("[*] No Imports Found In File")
    return has_antidbg

# Check file for sections with high entropy
def check_section_entropy(pe):
    if VERBOSE:
        print("\nCHECKING FOR HIGH ENTROPY SECTIONS:")
    high_entropy = False # Checking for high entropy sections
    if VERBOSE:
        print("\nNo.| Section Name |  VirtualAddress   |  VirtualSize    |  SizeOfRawData  |  Entropy \n")
    for section in pe.sections:
        # check if sections has high entropy - executables with a lot of compressed or encrypted data have higher entropy values; must be appropriately tuned 
        if section.get_entropy() > 7.2: 
            if VERBOSE:
                print("  %s    |     0x%x        |     0x%x      |      0x%x     |    %d   [SUSPICIOUS]" % (section.Name.decode("utf-8"), section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData, section.get_entropy()))
            high_entropy = True
    return high_entropy

# Check file for sections that are overlapped with one another
# Normally in a legitimate executable, the sections are not overlapped, and each section has a unique virtual address range. 
# However, in an executable infected with malware, the malware code may be overlapped with other sections, making it more difficult to detect.
def check_section_overlap(pe):
    if VERBOSE:
        print("\nCHECKING FOR OVERLAPPED SECTIONS:")
    has_overlap = False
    sections = [(section.VirtualAddress, section.Misc_VirtualSize) for section in pe.sections]
    sections.sort()
    for i in range(1, len(sections)):
        if sections[i][0] < sections[i - 1][0] + sections[i - 1][1]:
            has_overlap = True
            if VERBOSE:
                print("Section overlap detected")
    return has_overlap

# Check if file has any kernel-mode imports
def check_kernel_mode(pe):
    if VERBOSE:
        print("\nCHECKING FOR KERNEL-MODE IMPORTS:")
    has_kernelmode_imports = False
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if (entry.dll == "ntoskrnl.exe"): # ntoskrnl.exe is a system process, and it’s also known as the “Windows NT Operating System Kernel Executable”. 
                has_kernelmode_imports = True
                if VERBOSE:
                    print("   %s   [SUSPICIOUS]" % (entry.dll))
    except:
        pass
    return has_kernelmode_imports

# Check for any mismatches of file's sections' characteristics with known good characteristics (flags); e.g. .text --> 0x60000020
def check_section_characteristics(pe):
    if VERBOSE:
        print("\nCHECKING FOR MISMATCHED SECTION CHARACTERISTICS:")
    sec_characteristics_mismatched = False
    for sec in pe.sections:
        sec_name = sec.Name.replace(b'\x00', b'').decode('utf-8') # format section name
        if sec_name in characteristics_check_sections:
            sec_characteristics = hex(sec.Characteristics).lower() # perform a match of section characteristics with the standard (known good) values
            if characteristics_check_sections[sec_name] != sec_characteristics: # if mismatch, then append section name to list
                if VERBOSE:
                    print("  %s    |    %s  [SUSPICIOUS]" % (sec_name, sec_characteristics))
                sec_characteristics_mismatched = True
    return sec_characteristics_mismatched

# Check if file uses any anti-virtual machine techniques
def antivm(file):
    if VERBOSE:
        print("\nCHECKING FOR ANTI-VM TECHNIQUES:")
    has_antivm = False
    tricks = {
        "Red Pill": b"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
        "VirtualPc trick": b"\x0f\x3f\x07\x0b",
        "VMware trick": b"VMXh",
        "VMCheck.dll": b"\x45\xC7\x00\x01",
        "VMCheck.dll for VirtualPC": b"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
        "Xen": b"XenVMM",
        "Bochs & QEmu CPUID Trick": b"\x44\x4d\x41\x63",
        "Torpig VMM Trick": b"\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
        "Torpig (UPX) VMM Trick": b"\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
    }
    ret = []
    with open(file, "rb") as f:
        buf = f.read()
        for trick in tricks:
            pos = buf.find(tricks[trick])
            if pos > -1:
                ret.append("\t[+] 0x%x %s" % (pos, trick))
                has_antivm = True
    if VERBOSE:
        print(ret)
    return has_antivm

# Check if file uses any packers
def check_packers(pe):
    if VERBOSE:
        print("\nCHECKING FOR FILE PACKERS:")
    packers = []
    if sigs:
        matches = sigs.match(pe, ep_only=True) # checks for any matches to signatures of packers stored in PEID "database"
        if matches != None:
            for match in matches:
                packers.append(match)
    if VERBOSE:
        print(packers)
    return packers

# indicators of heuristically incorrect values would be those that are outside the VirtualSize of the code section.
def check_entry_point(pe):
    if VERBOSE:
        print("\nCHECKING FOR SUSPICIOUS ENTRY POINTS:")
    has_ep_out = False
    name = ''
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pos = 0
    for sec in pe.sections:
        if (ep >= sec.VirtualAddress) and (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
            name = sec.Name.replace(b'\x00', b'').decode('utf-8')
            break
        else:
            pos += 1
    ep_ava = ep + pe.OPTIONAL_HEADER.ImageBase
    if (name not in good_entry_point_sections) or pos == len(pe.sections):
        if VERBOSE:
            print("\n[*] Entry-Point Check ==> %s %s %d/%d [SUSPICIOUS]" % (hex(ep_ava), name, pos, len(pe.sections)))
        has_ep_out = True
    return has_ep_out

# Check for invalid checksum
# The checksum is generated using an algorithm specific to the PE format and is used to verify file integrity
def check_pe_checksum(pe):
    if VERBOSE:
        print("\nCHECKING FOR INVALID CHECKSUM:")
    invalid_checksum = False
    if pe.OPTIONAL_HEADER.CheckSum != 0 and pe.generate_checksum() != pe.OPTIONAL_HEADER.CheckSum:
        invalid_checksum = True
        if VERBOSE:
            print("Invalid checksum detected")
    return invalid_checksum

# Check for invalid timestamp
# Some AVs may use the timestamp value to determine the file's age, and flag files that are too old or too new
# By setting the timestamp value to zero, the malware does not provide any information about its age, making it harder for AVs to determine if the file is malicious
def check_pe_timestamp(pe):
    invalid_timestamp = False
    if pe.FILE_HEADER.TimeDateStamp == 0:
        invalid_timestamp = True
        if VERBOSE:
            print("\nCHECKING FOR INVALID TIMESTAMP:")
            print("Invalid timestamp detected")
    return invalid_timestamp

# Check for known suspicious resource types
def check_suspicious_resources(pe):
    if VERBOSE:
        print("\nCHECKING FOR SUSPICIOUS RESOURCES:")
    has_res = False # For Suspicious Resources
    try:
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = "%s" % resource_type.name
            else:
                name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
            if name == None:
                name = "%d" % resource_type.struct.Id
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                            if (name == "BINARY" or name == "RT_RCDATA"): # heuristically, there are a few resource types to watch out for, e.g. RT_RCDATA - it is often used by malware packers to store encrypted or obfuscated data.
                                if VERBOSE:
                                    print("  %s    |   0x%x        |   %d      |   %s  [SUSPICIOUS]" % (name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size, lang))
                                has_res = True
    except AttributeError:
        print("[*] No Resources Found In File")
    return has_res

# Check for Thread Local Storage (TLS) callbacks
def check_tls_callbacks(pe):
    has_tls_callbacks = False
    if VERBOSE:
        print("\nCHECKING FOR TLS CALLBACKS:")
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        callback_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
        if VERBOSE:
            print("[*] TLS callback functions array detected at 0x%x" % pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks) # Malwares employ TLS callbacks to evade debugger messages; when a particular malware employed with TLS callbacks is loaded into a debugger, the malware finishes its work before the debugger stops at the entry point.
            print("\t[*] Callback Array RVA 0x%x" % callback_rva)
        has_tls_callbacks = True
    else:
        if VERBOSE:
            print("\n[*] No TLS Callbacks Detected ...")
    return has_tls_callbacks
         
# Check that section alignment and file alignment are heuristically correct            
def check_alignments(pe):
    if VERBOSE:
        print("\nCHECKING FOR INVALID ALIGNMENTS:")
    invalid_alignment = False
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    base_of_code = pe.OPTIONAL_HEADER.BaseOfCode
    if base_of_code != section_alignment:
        if VERBOSE:
            print("Base of code does not match section alignment")
        invalid_alignment = True
    if section_alignment != 4096:
        if VERBOSE:
            print("Invalid section alignment: %s" % section_alignment)
        invalid_alignment = True
    if file_alignment != 512:
        if VERBOSE:
            print("Invalid file alignment: %s" % file_alignment)
        invalid_alignment = True
    return invalid_alignment
                
# Main function to invoke all other heuristic helper functions
def pe_heuristics_detection(logger, remote_logger, file_path, file_name):
    if not os.path.exists(file_path):
        logger.log("ERROR", "FileHeuristics", "Non-Existent File %s ... " % file_name)
        do_remote_logging(remote_logger, "ERROR", ["FileHeuristics", "Non-Existent File %s ... " % file_name])
        return None
    logger.log("INFO", "FileHeuristics", "Performing Heuristics Check on File %s ... " % file_name)
    do_remote_logging(remote_logger, "INFO", ["FileHeuristics", "Performing Heuristics Check on File %s ... " % file_name])
    pe = pefile.PE(file_path)  # Loading the PE file

    alerts_list = []

    has_antidbg = check_antidbg(pe)
    has_res = check_suspicious_resources(pe)
    has_overlap = check_section_overlap(pe)
    high_entropy = check_section_entropy(pe)
    has_antivm = antivm(file_path)
    has_kernelmode_imports = check_kernel_mode(pe)
    has_ep_out = check_entry_point(pe)
    # has_tls_callbacks = check_tls_callbacks(pe)
    invalid_alignment = check_alignments(pe)
    invalid_timestamp = check_pe_timestamp(pe)
    invalid_checksum = check_pe_checksum(pe)
    packers_list = check_packers(pe)

    if has_res:
        alerts_list.append("This executable has some suspicious resources")
    if has_overlap:
        alerts_list.append("This executable has some sections that are overlapped")
    if has_antivm:
        alerts_list.append("This executable has anti-virtual machine tricks")
    if has_ep_out:
        alerts_list.append("This executable has entry point outside known good sections")
    if high_entropy:
        alerts_list.append("This executable has high entropy values (probably packed or compressed)")
    if has_kernelmode_imports:
        alerts_list.append("This executable uses kernel mode (probably a system driver)")
    if has_antidbg:
        alerts_list.append("This executable uses anti-debugging tricks")
    # if has_tls_callbacks:
    #     alerts_list.append("This executable has TLS callbacks")
    if invalid_alignment:
        alerts_list.append("This executable has suspicious section and/or file alignments")
    if invalid_timestamp:
        alerts_list.append("This executable has an invalid timestamp")
    if invalid_checksum:
        alerts_list.append("This executable has an invalid checksum")
    
    pe.close()
    
    # Can give verdict based on matching of certain set of rules (ultimately depends on trade-offs between false negatives and false positives), e.g.
    
    if len(alerts_list) >= 3:
        verdict = "DANGEROUS"
    else:
        verdict = "SAFE"       
        
    logger.log(verdict, "FileHeuristics", "FILE: %s HEURISTICS VERDICT: %s " % (file_name, verdict))
    do_remote_logging(remote_logger, verdict, ["FileHeuristics", "FILE: %s HEURISTICS VERDICT: %s " % (file_name, verdict)])

    return verdict, alerts_list
    
if __name__ == '__main__':
    file_path = os.path.join("C:\\Users\\Javier Tan\\Downloads", "MSTeamsSetup_c_l_.exe")
    print(pe_heuristics_detection(None, None, file_path, "MicrosoftEdgeSetup.exe"))

