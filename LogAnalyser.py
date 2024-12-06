# Import the Neccessary Libraries
import os
import sys
import re
from datetime import datetime

def makePatternObject():
    """
        This will return the Pattern Object
    """
    pattern = r"(?P<ip>[\d\.]+) - - \[(?P<datetimestamp>[^\]]+)\] \"(?P<method>[A-Z]+) (?P<path>[^\s]+) (?P<http_version>[^\"]+)\" (?P<status>[\d]+) (?P<size>[\d]+)(?: \"(?P<message>.*?)\")?"
    obj = re.compile(pattern)
    return obj

def extractFromLine(line,pattern):
    """
        This will extract the named groups and return a dictionary
    """
    match = pattern.match(line)
    return match.groupdict()

def processFile(file_path):
    pattern_object = makePatternObject()
    ip_dict = {}
    endpoint_dict = {}
    activity_dict = {}
    with open(file_path, mode="r") as File:
        line = File.readline()
        while line:
            extracted_items = extractFromLine(line, pattern_object)
            if extracted_items["ip"] not in ip_dict:
                ip_dict[extracted_items["ip"]] = 1
                continue
            else:
                ip_dict[extracted_items["ip"]] += 1
            if extracted_items["path"] not in endpoint_dict:
                endpoint_dict[extracted_items["ip"]] = 1
                continue
            else:
                endpoint_dict["path"] += 1
            line = File.readline()
    print(ip_dict)
    print(endpoint_dict)

if __name__ == "__main__":
    # Get the arguments
    arguments = sys.argv
    # Check if file path is given
    if(len(arguments) <= 1):
        sys.exit("File Required")
    # If given then run the loop
    for arg in arguments[1:]:
        processFile(arg)