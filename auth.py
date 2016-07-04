#!/usr/bin/env python3

import urllib.request, ssl
from http.cookiejar import CookieJar, DefaultCookiePolicy
import argparse
from bs4 import BeautifulSoup
import sys
from pprint import pprint
from urllib.parse import urljoin
import re

ARGS = argparse.ArgumentParser(description="ms-ff-uag-tcp")
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.75 Safari/537.36"
ACCEPT = "*/*"


ARGS.add_argument(
    '--domain', action="store", dest='domain',
    default='localhost', type=str, help='Domain of MS ForeFront UAG')

ARGS.add_argument(
    '--cafile', action="store", dest='cafile',
    default='creds/cacert.pem', type=str, help='Certificate chain for the UAG https')

ARGS.add_argument(
    '--auth', action="store", dest='auth',
    default='creds/auth.txt', type=str, help='Username and password in plaintext separated by a new line')


args = ARGS.parse_args()
with open(args.auth, 'r') as args.auth:
    auth_creds = args.auth.read()


ctx = ssl.create_default_context(cafile=args.cafile)

policy = DefaultCookiePolicy()#rfc2965=True, strict_ns_domain=DefaultCookiePolicy.DomainStrict, blocked_domains=["ads.net", ".ads.net"])
cj = CookieJar(policy)
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(cj))
url = urllib.request.Request("https://" + args.domain + "/")
url.add_header("User-Agent", USER_AGENT)
url.add_header("Accept", ACCEPT)
pprint(url.header_items())
#sys.exit()
r = opener.open(url)

login_url = r.url
html_doc = r.read().decode('utf-8')
print(login_url)
print(html_doc)

soup = BeautifulSoup(html_doc, 'html.parser')
post_url = soup.find(id="form1").get("action")

uag_dummy_repository = soup.find(id="form1").find("input", {"name": "dummy_repository"}).get("value")
uag_repository = soup.find(id="form1").find("input", {"name": "repository"}).get("value")


post_data = {
	"dummy_repository": uag_dummy_repository,
	"repository": uag_repository,
	"user_name": auth_creds.split("\n")[0],
	"password": auth_creds.split("\n")[1],

	"site_name": "fileaccess",

	"secure": "1",
	"resource_id": "2",
	"login_type": "3",
}

details = urllib.parse.urlencode(post_data).encode('UTF-8')
url = urllib.request.Request( urljoin(login_url, post_url) , details)
url.add_header("User-Agent", USER_AGENT)
url.add_header("Accept", ACCEPT)

r = opener.open(url)

html_doc = r.read().decode('utf-8', 'ignore');
new_url = re.search('window\.location\.replace\("([^"]+)"\)', html_doc).group(1)

print(r.url)
print(html_doc)

url = urllib.request.Request( urljoin(r.url, new_url))
url.add_header("User-Agent", USER_AGENT)
url.add_header("Accept", ACCEPT)

r = opener.open(url)

html_doc = r.read().decode('utf-8', 'ignore');

print(r.url)
print(html_doc)
