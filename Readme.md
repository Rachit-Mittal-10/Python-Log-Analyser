# Python Log Analyser

This is the script that will analyse the logs of http server like Apache or Nginx.

It will output 3 things:-

1. Requests made per IP Address

2. Most Accessed End Point

3. Suspicious Activity Detected

To run this script, User needs to have python installed in it's system. 

## Prerequistes:

- Python: Go to [Python Official Webiste](https://www.python.org/downloads/) to download the Python from there for your Operating Systems.

- Pandas
```
pip install -r Requirements.txt
```

## How to run

- Write the appropriate file name in LOG_FILE_PATH variable
- Execute the script

For Linux
```
    python3 logAnalyserScript
```

For Windows
```
    python logAnalsyerScript
```