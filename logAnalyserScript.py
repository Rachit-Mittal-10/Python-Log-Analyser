# Importing the neccessary libraries
import re
import pandas as pd
import sys
from datetime import datetime
import os


class LogAnalyser:
    """
        This is the class that encapsulates the all the related methods
    """

    def __init__(self, log_file_path):
        self._pattern_object = self._makePatternObject()
        self._LOG_FILE_PATH = log_file_path
        self._array_dicts = self._readFileAndGetArray()
        self._df = self._getDF()
    
    @staticmethod
    def _makePatternObject():
        """
            This will return the Pattern Object
        """
        pattern = r"(?P<ip>[\d\.]+) - - \[(?P<datetimestamp>[^\]]+)\] \"(?P<method>[A-Z]+) (?P<path>[^\s]+) (?P<http_version>[^\"]+)\" (?P<status>[\d]+) (?P<size>[\d]+)(?: \"(?P<message>.*?)\")?"
        obj = re.compile(pattern)
        return obj

    def _extractFromLine(self,line):
        """
            This will extract the named groups and return a dictionary
        """
        pattern = self._pattern_object
        match = pattern.match(line)
        return match.groupdict()

    def _readFileAndGetArray(self):
        pattern_object = self._pattern_object
        array_dicts = []
        with open(self._LOG_FILE_PATH, mode="r") as File:
            lines = File.readlines()
            for line in lines:
                array_dicts.append(self._extractFromLine(line))
        return array_dicts
    
    def _getDF(self):
        """
            This function returns the DataFrame created from array of dicts
        """
        return pd.DataFrame(self._array_dicts)

    def _countRequestPerIP(self):
        """
            This function will print the count the requests per IP
        """
        df = self._df
        grouped_df = df.groupby(by="ip").size().reset_index(name="count").sort_values(by="count",ascending=False)
        grouped_df.columns = ["IP Address", "Request Count"]
        return grouped_df

    def _countPathAndPrintMaxRequestedPath(self):
        """
            This function will print the maximum accessed path
        """
        df = self._df
        grouped_df = df.groupby(by="path").size()
        index = grouped_df.idxmax()
        value = grouped_df[index]
        return pd.DataFrame({
            "End Point": [index],
            "Access Count": [value]
        },)

    def _detectSuspiciousActivity(self, login_threshold=10):
        """
            This function will detect suspicious activity and print it.
        """
        df = self._df
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
    def logAnalyser(self):
        """
            This will analyse the log file and write output to terminal and file.
        """
        print("Task-1")
        task1 = self._countRequestPerIP()
        print(task1)
        print()
        print("Task-2")
        print("Most Frequently Accessed Endpoints")
        task2 = self._countPathAndPrintMaxRequestedPath()
        print(task2)
        print()
        print("Task-3")
        print("Suspicious Activity Detected")
        task3 = self._detectSuspiciousActivity()
        print(task3)
        
        # This will write to file
        base_name = os.path.basename(self._LOG_FILE_PATH)
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
        if not os.path.exists(arg):
            print(f"{arg} not exist")
            continue
        LogAnalyser(arg).logAnalyser()