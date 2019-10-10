# phishfinder

## Overview
The tool will traverse a URL path to find open directories. If found, it will then look for any zip/txt/exe files and download them. The likelihood is these files will contain the phishing source code, victim logs and possibly malware. You can supply a list of urls in a text file, or by default the code will connect to phishtank and parse the latest known phishing urls. 

Additionally, the tool will also attempt to guess the name of the .zip, as commonly this is the same as the current URI folder, e.g.

    https://example.com/foo/bar.zip
    https://example.com/foo.zip
    
## Usage
Run the script without any arguments to use the latest URLs from http://data.phishtank.com/data/online-valid.json 
    
    python3 phishfinder.py

Else, you can pass a list of URLs and specify the folder where you'd like to save results

    python3 phishfinder.py --input urls.txt --output /phishing/kit/folder

## Example

![phishfinder example](/../screenshots/render1551268365598.gif?raw=true "Phishfinder Example")

## Install
    $ pip3 install -r requirements.txt

## TODO

Updates planned include:

* ~~Brute-forcing for files using the directory as the filename~~
* Brute-forcing of victim log files from common txt file naming conventions
* Speed up the requests and use threading
* Get down with the cool katz and re-write this in Go.
* ~~Resolve issue where a successful guess downloads a file, followed by an Open Directory download~~

