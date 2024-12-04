# Importing the neccessary libraries
import re
import pandas as pd
from sys import getsizeof


def makePatterObject():
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
    pattern_object = makePatterObject()
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
    return grouped_df

def countPathAndPrintMaxRequestedPath(array_dicts):
    """
        This function will print the maximum accessed path
    """
    df = getDF(array_dicts)
    grouped_df = df.groupby(by="path").size()
    index = grouped_df.idxmax()
    value = grouped_df[index]
    return (index, value)

def detectSuspiciousActivity(array_dicts, login_threshold=10):
    """
        This function will detect suspicious activity and print it.
    """
    df = getDF(array_dicts)
    length = len(df)
    return_dict = {}
    for index in range(length):
        ip = df.iloc[index].iloc[0]
        status = df.iloc[index].iloc[-3]
        if ip not in return_dict and status == "401":
            return_dict[ip] = 1
            continue
        if ip in return_dict and status == "401":
            return_dict[ip] += 1
    return return_dict 


# main function
def main():
    LOG_FILE_PATH = "./sample.log"
    array_dicts = readFileAndGetArray(LOG_FILE_PATH)
    print("Task-1")
    task1 = countRequestPerIP(array_dicts)
    print(task1)
    print()
    print("Task-2")
    print("Most Frequently Accessed Endpoints")
    task2 = countPathAndPrintMaxRequestedPath(array_dicts)
    print(f"{task2[0]}\t\t(Accessed {task2[1]} times)")
    print()
    print("Task-3")
    print("Suspicious Activity Detected")
    answer_dict = detectSuspiciousActivity(array_dicts)
    print("IP Adress\t\t\tFailed Attempt")
    for key in answer_dict:
        print(f"{key}\t\t\t{answer_dict[key]}")
    print()
main()