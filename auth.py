#!/usr/bin/env python3

import urllib.request, ssl
from urllib.parse import urljoin, quote
from http.cookiejar import CookieJar, DefaultCookiePolicy

import mimetypes
import email.generator

from bs4 import BeautifulSoup

import re
import sys
import argparse
from pprint import pprint


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = email.generator._make_boundary()
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: application/octet-stream' % (mimetypes.guess_type(filename)[0] or 'application/octet-stream'))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body.encode('utf-8')


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

ARGS.add_argument(
    '--dir', action="store", dest='dir',
    default='', type=str, help='Directory in MS FF')




def perform_auth(opener):
    url = urllib.request.Request("https://" + args.domain + "/")
    url.add_header("User-Agent", USER_AGENT)
    url.add_header("Accept", ACCEPT)

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

    main_url = r.url
    print(r.url)
    print(html_doc)

    return main_url

def create_folder(opener, main_url, folder_name):
    
    folder = args.dir + "/" + folder_name
    folder_escaped = quote(folder, safe='')

    create_folder_url = urljoin(main_url, "../filesharing/newfolder.asp?Folder=" + folder_escaped)

    content_type, body = encode_multipart_formdata([("Filedata",folder_name), ("remotefile",args.dir), ("submit1", "Create Folder")], {})

    url = urllib.request.Request(create_folder_url , body)

    url.add_header("User-Agent", USER_AGENT)
    url.add_header("Accept", ACCEPT)
    url.add_header("Content-Type", content_type)
    url.add_header("Content-Length", str(len(body)) )

    r = opener.open(url)
    html_doc = r.read().decode('utf-8', 'ignore');

    return html_doc


def list_folder(opener, main_url, folder_name):
    
    folder = args.dir + "/" + folder_name
    folder_escaped = quote(folder, safe='')

    create_folder_url = urljoin(main_url, "../filesharing/filelist.asp?S=" + folder_escaped + "&T=9")

    url = urllib.request.Request(create_folder_url)

    url.add_header("User-Agent", USER_AGENT)
    url.add_header("Accept", ACCEPT)

    r = opener.open(url)
    html_doc = r.read().decode('utf-8', 'ignore');


    soup = BeautifulSoup(html_doc, 'html.parser')
    file_nodes = soup.find(id="fileListTable").find("tbody").find_all("label")
    return_arr = []
    for i in file_nodes:
        if i.get("onmousedown").find('isFile = true') != -1:
            isFile = True
        else:
            isFile = False

        return_arr.append((isFile, i.find('nobr').text))
    return return_arr


if __name__ == '__main__':

    args = ARGS.parse_args()
    with open(args.auth, 'r') as args.auth:
        auth_creds = args.auth.read()

    ctx = ssl.create_default_context(cafile=args.cafile)
    cj = CookieJar(DefaultCookiePolicy(rfc2965=True, strict_ns_domain=DefaultCookiePolicy.DomainStrict, blocked_domains=["ads.net", ".ads.net"]))
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(cj))

    main_url = perform_auth(opener)
    create_folder(opener, main_url, 'testing-folders')
    pprint(list_folder(opener, main_url, ''))
