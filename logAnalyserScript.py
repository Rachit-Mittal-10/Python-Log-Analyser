# Importing the neccessary libraries
import re
import pandas as pd
from sys import getsizeof


def makePatterObject():
    """
        This will return the Pattern Object
    """
    pattern = r"^(?P<ip>[\d\.]+) - - \[(?P<datetimestamp>[^\]]+)\] \"(?P<method>[A-Z]+) (?P<path>[^\s]+) (?P<http_version>[^\"]+)\" (?P<status>[\d]+) (?P<size>[\d]+)"
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
    print(f"Size of Array: {getsizeof(array_dicts)}")
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
    print(f"Size of DF: {getsizeof(df)}")
    print("Task1: Count Request per ip")
    print(df.groupby(by="ip").size().reset_index(name="count").sort_values(by="count",ascending=False))
    print()

def countPathAndPrintMaxRequestedPath(array_dicts):
    """
        This function will print the maximum accessed path
    """
    df = getDF(array_dicts)
    print("Task2: Print the Maximum Accessed Endpoint")
    grouped_df = df.groupby(by="path").size()
    index = grouped_df.idxmax()
    value = grouped_df[index]
    print(f"Most Accessed Endpoint is {index} for {value} times")
    print()

def detectFailedLogin(array_dicts):
    """
        This functioln will detect the failed login attempts.
    """

    pass

def flagIP(array_dicts, login_threshold=10):
    """
        This function will flg the IP with login more than threshold.
    """
    pass

def detectSuspiciousActivity(array_dicts):
    """
        This function will detect suspicious activity and print it.
    """
    detectFailedLogin(array_dicts)
    flagIP(array_dicts)

def main():
    LOG_FILE_PATH = "./sample.log"
    array_dicts = readFileAndGetArray(LOG_FILE_PATH)
    countRequestPerIP(array_dicts)
    countPathAndPrintMaxRequestedPath(array_dicts)
    detectSuspiciousActivity(array_dicts)


main()