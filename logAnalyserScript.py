# Importing the neccessary libraries
import re
import pandas as pd
import sys
from datetime import datetime
import os

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

def readFileAndGetArray(filePath):
    pattern_object = makePatternObject()
    array_dicts = []
    with open(filePath, mode="r") as File:
        lines = File.readlines()
        for line in lines:
            array_dicts.append(extractFromLine(line,pattern_object))
    return array_dicts

def getDF(array_dicts):
    """
        This function returns the DataFrame created from array of dicts
    """
    return pd.DataFrame(array_dicts)

def countRequestPerIP(array_dicts):
    """
        This function will print the count the requests per IP
    """
    df = getDF(array_dicts)
    grouped_df = df.groupby(by="ip").size().reset_index(name="count").sort_values(by="count",ascending=False)
    grouped_df.columns = ["IP Address", "Request Count"]
    return grouped_df

def countPathAndPrintMaxRequestedPath(array_dicts):
    """
        This function will print the maximum accessed path
    """
    df = getDF(array_dicts)
    grouped_df = df.groupby(by="path").size()
    index = grouped_df.idxmax()
    value = grouped_df[index]
    return pd.DataFrame({
        "End Point": [index],
        "Access Count": [value]
    },)
    # return (index, value)

def detectSuspiciousActivity(array_dicts, login_threshold=10):
    """
        This function will detect suspicious activity and print it.
    """
    df = getDF(array_dicts)
    length = len(df)
    return_dict = {}
    for index in range(length):
        ip = df.iloc[index]["ip"]
        status = df.iloc[index]["status"]
        if ip not in return_dict and status == "401":
            return_dict[ip] = 1
            continue
        if ip in return_dict and status == "401":
            return_dict[ip] += 1
    return pd.DataFrame(list(return_dict.items()),columns=["IP Address", "Failed Login Count"])


# main function
def logAnalyser(LOG_FILE_PATH):
    # This will read the file and get the array of lines
    array_dicts = readFileAndGetArray(LOG_FILE_PATH)
    
    # Following block of code processes the log file
    print("Task-1")
    task1 = countRequestPerIP(array_dicts)
    print(task1)
    print()
    print("Task-2")
    print("Most Frequently Accessed Endpoints")
    task2 = countPathAndPrintMaxRequestedPath(array_dicts)
    print(task2)
    print()
    print("Task-3")
    print("Suspicious Activity Detected")
    task3 = detectSuspiciousActivity(array_dicts)
    print(task3)
    
    # This will write to file
    base_name = os.path.basename(LOG_FILE_PATH)
    with open(f"./LogAnalyserResult-{base_name}-{datetime.now()}.csv","w") as Writer:
        Writer.write("Requests per ip\n")
        task1.to_csv(Writer, index=False)
        Writer.write("\n")
        Writer.write("Most Accessed End Point\n")
        task2.to_csv(Writer,index=False)
        Writer.write("\n")
        Writer.write("Suspicious Activity\n")
        task3.to_csv(Writer,index=False)
        Writer.write("\n")
    return

if __name__ == "__main__":
    # Get the arguments
    arguments = sys.argv
    # Check if file path is given
    if(len(arguments) <= 1):
        sys.exit("File Required")
    # If given then run the loop
    for arg in arguments[1:]:
        logAnalyser(arg)