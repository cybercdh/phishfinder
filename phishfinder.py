'''
  phishfinder.py
  written by colin hardy
  https://twitter.com/cybercdh

  description:
  the tool will traverse a url path to find open diretories
  if found, it will then look for any zip files and download them
  the likelihood is, these .zip files will contain the phishing source code

  you can supply a list of urls in a text file, or by default the code 
  will connect to phishtank and parse the latest known urls. 

  usage:
  python phishfinder.py
  python phishfinder.py [--input urls.txt] [--logfile somelogfile.txt]

  released under MIT licence.

'''
import requests
import csv
import sys
import os.path
import json
from urlparse import urlparse, urljoin
from bs4 import BeautifulSoup
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-i", "--input", dest="inputfile", required=False, help="input file of phishing URLs", metavar="FILE")
parser.add_argument("-l", "--logfile", dest="logfile", default="phish_log.txt", help="output log file location", metavar="FILE")
args = parser.parse_args()

# colors used for prettifying up the terminal output
class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    ENDC = '\033[0m'

def go_phishing(phishing_url):
  # parts returns an array including the path. Split the paths into a list to then iterate
  # e.g. ParseResult(scheme='https', netloc='example.com', path='/hello/world/foo/bar', params='', query='', fragment='')
  parts = urlparse(phishing_url)
  paths = parts.path.split('/')[1:]

  # iterate the length of the paths list
  for i in range(0, len(paths)):

    # traverse the path
    phish_url = '{}://{}/{}/'.format(parts.scheme, parts.netloc,'/'.join(paths[:len(paths) - i]))
    
    # make the request
    try:
      r = requests.get(phish_url, allow_redirects=False, timeout=5)
    except requests.exceptions.RequestException:
      print bcolors.WARNING + "[!]  An error occurred connecting to {}".format(phish_url) + bcolors.ENDC
      return 

    if not r.ok:
      return
    
    print "[+]  Checking: {}".format(phish_url)

    # check if directory listing is enabled
    if "Index of" in r.text:
      print "[!]  Directory found at {}".format(phish_url)

      # get all the links in the directory
      soup = BeautifulSoup(r.text, 'html.parser')
      for a in soup.find_all('a'):

          # skip parent directory link
          if 'Parent Directory' in a.text:
            continue

          # skip invalid hrefs
          href = a['href']
          if href and href[0] == '?':
            continue

          # if it's a .zip, we're interested
          if href.endswith(".zip"):

            # get the full path of the kit
            kit_url = urljoin(phish_url, href)
            filename = kit_url.split('/')[-1]
            print bcolors.OKGREEN + "[!]  Possible phishing kit found at {}".format(kit_url) + bcolors.ENDC
            
            # update the log file
            f = open (args.logfile, "a")
            f.write(kit_url + "\n")

            # download the kit, save to the current directory, stream it as opposed to save in memory
            try:
              q = requests.get(kit_url, allow_redirects=False, timeout=5, stream=True)
            except requests.exceptions.RequestException:
              print bcolors.WARNING + "[!]  An error occurred downloading the phishing kit at {}".format(kit_url) + bcolors.ENDC
              return

            if q.ok:
              sys.stdout.write('[+]  Saving file to ./%s...' % filename)
              with open (filename, 'wb') as kit:
                for chunk in q.iter_content(chunk_size=1024):
                  if chunk:
                    kit.write(chunk)
                print bcolors.OKGREEN + "saved." + bcolors.ENDC


def use_phishtank():
  # it does take a min or so to parse the json
  sys.stdout.write('[+]  Parsing URLs from phishtank, this may take a minute...')
  sys.stdout.flush()
  try:  
    r = requests.get("http://data.phishtank.com/data/online-valid.json", allow_redirects=True, timeout=5, stream=True)
  except requests.exceptions.RequestException:
    print bcolors.WARNING + "[!]  An error occurred connecting to phishtank. Please try again." + bcolors.ENDC
    sys.exit()

  if not r.ok:
    sys.exit()

  parsed_json = r.json()
  print bcolors.OKGREEN + "done." + bcolors.ENDC

  # go phishing baby!
  for entry in parsed_json:
    url = entry['url'].strip()
    go_phishing(url)

def use_local_file(f):
  # check the file exists
  if not os.path.isfile(f):
    print bcolors.WARNING + "[!]  {} is not a valid file. Please retry".format(f) + bcolors.ENDC
    sys.exit()

  # parse the urls and go phishing
  print bcolors.WARNING + "[+]  Checking URLs from {}".format(f) + bcolors.ENDC
  with open (f) as inputfile:
    urls = inputfile.readlines()
    for url in urls:
      url = url.strip()
      go_phishing(url)

def main():
  # if the user supplies a list of urls, use that, else connect to phishtank
  if args.inputfile is not None:
    use_local_file(args.inputfile)
  else:
    use_phishtank()

if __name__ == "__main__":
  main()


