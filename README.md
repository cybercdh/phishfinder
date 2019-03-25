# phishfinder

## Overview
The tool will traverse a url path to find open directories. If found, it will then look for any zip/txt/exe files and download them. The likelihood is these files will contain the phishing source code, victim logs and possibly malware. You can supply a list of urls in a text file, or by default the code will connect to phishtank and parse the latest known urls. 

## Usage
Run the script without any arguments to use the latest URLs from http://data.phishtank.com/data/online-valid.json
    
    python phishfinder.py

Else, you can pass a list of URLs and also a logfile location of your choice to record which URLs were related to each kit found.

    python phishfinder.py --input urls.txt --logfile somelogfile.txt --output /phishing/kit/folder

## Example

![phishfinder example](/../screenshots/render1551268365598.gif?raw=true "Phishfinder Example")

