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
  python phishfinder.py [--input urls.txt] [--output /some/folder]

  released under MIT licence.

'''
import requests
import csv
import sys
import os, os.path
import errno
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin, unquote
from bs4 import BeautifulSoup
from argparse import ArgumentParser
from colorama import init
from clint.textui import progress
init()

parser = ArgumentParser()
parser.add_argument("-i", "--input", dest="inputfile", required=False, help="input file of phishing URLs", metavar="FILE")
parser.add_argument("-o", "--output", dest="outputDir", default=".", help="location to save phishing kits and logs", metavar="FILE")
args = parser.parse_args()

LASTURL = "" # stores the lastest phishing kit url

# colors used for prettifying up the terminal output
class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    ENDC = '\033[0m'

# Taken from https://stackoverflow.com/questions/23793987/write-file-to-a-directory-that-doesnt-exist
def mkdir_p(path):
  try:
      os.makedirs(path)
  except OSError as exc: # Python >2.5
      if exc.errno == errno.EEXIST and os.path.isdir(path):
          pass
      else: raise

def safe_open_w(path):
  mkdir_p(os.path.dirname(path))
  return open(path, 'wb')

def safe_open_a(path):
  mkdir_p(os.path.dirname(path))
  return open(path, 'a')

def go_guessing(phish_url):
  # append .zip to the current path, and see if it works!
  guess_url = phish_url[:-1] + ".zip" 
  
  if guess_url[-5:] != "/.zip": 
    print("[+]  Guessing: {}".format(guess_url))

    try:
      g = requests.head(guess_url, allow_redirects=False, timeout=2, stream=True)

      # if there's no content-type, ignore
      if not 'content-type' in g.headers:
        return

      # if the content-type isn't a zip, ignore
      if not 'zip' in g.headers.get('content-type'):
        return

      # hopefully we're working with a .zip now...
      print(bcolors.OKGREEN + "[!]  Successful guess! Potential kit found at {}".format(guess_url) + bcolors.ENDC)
      download_file(guess_url)
      return 

    except requests.exceptions.RequestException:
      print("[!]  An error occurred connecting to {}".format(guess_url))
      return

def go_phishing(phishing_url):
  # parts returns an array including the path. Split the paths into a list to then iterate
  # e.g. ParseResult(scheme='https', netloc='example.com', path='/hello/world/foo/bar', params='', query='', fragment='')
  parts = urlparse(phishing_url)
  paths = parts.path.split('/')[1:]

  # iterate the length of the paths list
  for i in range(0, len(paths)):

    # traverse the path
    # phish_url = '{}://{}/{}/'.format(parts.scheme, parts.netloc,'/'.join(paths[:len(paths) - i]).encode('utf-8'))
    phish_url = '{}://{}/{}/'.format(parts.scheme, parts.netloc,'/'.join(paths[:len(paths) - i]))
    
    # guess each path with .zip extension
    go_guessing(phish_url)

    # request each path
    try:
      r = requests.get(phish_url, allow_redirects=False, timeout=2)
    except requests.exceptions.RequestException:
      print("[!]  An error occurred connecting to {}".format(phish_url))
      return 

    if not r.ok:
      return
    
    print("[+]  Checking: {}".format(phish_url))

    # check if directory listing is enabled
    if "Index of" in r.text:
      print(bcolors.WARNING + "[!]  Directory found at {}".format(phish_url) + bcolors.ENDC)
      
      # log open directories
      with safe_open_a(args.outputDir + "/directories.txt") as f:
        f.write(phish_url + "\n")

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

          # look for zips, txt and exes
          if href.endswith(".zip"):
            kit_url = urljoin(phish_url, href)
            print(bcolors.OKGREEN + "[!]  Possible phishing kit found at {}".format(kit_url) + bcolors.ENDC)
            download_file (kit_url)

          if href.endswith(".txt"):
            txt_url = urljoin(phish_url, href)
            print(bcolors.OKGREEN + "[!]  Possible victim list found at {}".format(txt_url) + bcolors.ENDC)
            download_file (txt_url)

          if href.endswith(".exe"):
            mal_url = urljoin(phish_url, href)
            print(bcolors.OKGREEN + "[!]  Possible malware found at {}".format(mal_url) + bcolors.ENDC)
            download_file (mal_url)

def download_file(download_url):

  # make sure the URL we're downloading hasn't just been guessed
  global LASTURL

  if (LASTURL == download_url):
    print(bcolors.WARNING + "[!]  Already downloaded {}".format(download_url) + bcolors.ENDC)    
    return

  LASTURL = download_url

  # current date and time for logging
  now = datetime.now() 
  date_time = now.strftime("%m%d%Y%H%M%S-")
  filename = date_time + download_url.split('/')[-1]

  # update the log file
  with safe_open_a(args.outputDir + "/kits.txt") as f:
    f.write(date_time + download_url + "\n")

  # download the kit
  try:
    q = requests.get(download_url, allow_redirects=False, timeout=5, stream=True)
    if q.ok:
      total_length = int(q.headers.get('content-length'))
      sys.stdout.write('[+]  Saving file to {0}{1}{2}...'.format(args.outputDir + "/kits", "/", filename))
      with safe_open_w(args.outputDir + "/kits/" + filename) as kit:
        for chunk in progress.bar(q.iter_content(chunk_size=1024), expected_size=(total_length/1024) + 1): 
          if chunk:
            kit.write(chunk)
            kit.flush()
        print(bcolors.OKGREEN + "saved." + bcolors.ENDC)
  except:
    print(bcolors.WARNING + "[!]  An error occurred downloading the file at {}".format(download_url) + bcolors.ENDC)
    return

def use_phishtank():
  # it does take a min or so to parse the json
  sys.stdout.write('[+]  Parsing URLs from phishtank, this may take a minute...')
  sys.stdout.flush()
  phishtank_url = "http://data.phishtank.com/data/online-valid.json"
  headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36'
  }
  try:  
    r = requests.get(phishtank_url, allow_redirects=True, timeout=5, stream=True, headers=headers)
  except requests.exceptions.RequestException:
    print(bcolors.WARNING + "[!]  An error occurred connecting to phishtank. Please try again." + bcolors.ENDC)
    sys.exit()

  if not r.ok:
    print(bcolors.WARNING + "[!]  An error occurred connecting to phishtank. Please try again." + bcolors.ENDC)
    sys.exit()

  parsed_json = r.json()
  print(bcolors.OKGREEN + "done." + bcolors.ENDC)

  # go phishing baby!
  for entry in parsed_json:
    url = entry['url'].strip()
    url = unquote(url)
    go_phishing(url)

def use_local_file(f):
  # check the file exists
  if not os.path.isfile(f):
    print(bcolors.WARNING + "[!]  {} is not a valid file. Please retry".format(f) + bcolors.ENDC)
    sys.exit()

  # parse the urls and go phishing
  print(bcolors.WARNING + "[+]  Checking URLs from {}".format(f) + bcolors.ENDC)
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


