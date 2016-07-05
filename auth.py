#!/usr/bin/env python3

import asyncio
try:
    import signal
except ImportError:
    signal = None
import logging
    
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

import datetime
import random

log = logging.getLogger(__name__)

BUFFER_SIZE = 1024*768
NEXT_TICK = 0.001 

def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = bytes(email.generator._make_boundary().replace('=','-'), 'ascii')
    CRLF = b'\r\n'
    L = []
    for (key, filename, value) in files:
        L.append(b'--' + BOUNDARY)
        L.append(b'Content-Disposition: form-data; name="%b"; filename="%b"' % 
            (bytes(key,'ascii'), bytes(filename,'ascii')))
        L.append(b'Content-Type: %b' % 
            bytes((mimetypes.guess_type(filename)[0] or 'application/octet-stream'), 'ascii') )
        L.append(b'')
        L.append(value)
    for (key, value) in fields:
        L.append(b'--' + BOUNDARY)
        L.append(b'Content-Disposition: form-data; name="%b"' % bytes(key,'ascii'))
        L.append(b'')
        L.append(bytes(value,'ascii'))
    L.append(b'--' + BOUNDARY + b'--')
    L.append(b'')
    
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body#.encode('utf-8')


ARGS = argparse.ArgumentParser(description="ms-ff-uag-tcp")
USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/50.0.2661.75 Safari/537.36") # modern UA, otherwise it thinks i'm on mobile

ACCEPT = "*/*"


ARGS.add_argument(
    '--domain', action="store", dest='domain',
    default='localhost', type=str, help='Domain of MS ForeFront UAG')

ARGS.add_argument(
    '--cafile', action="store", dest='cafile',
    default='creds/cacert.pem', type=str, help='Certificate chain for the UAG https')

ARGS.add_argument(
    '--auth', action="store", dest='auth',
    default='creds/auth.txt', type=str, 
    help='Username and password in plaintext separated by a new line')

ARGS.add_argument(
    '--dir', action="store", dest='dir',
    default='', type=str, help='Directory in MS FF')


ARGS.add_argument(
    '--server', action="store_true", dest='server',
     help='connect it to the server')


ARGS.add_argument(
    '--quiet', action="store", dest='quiet',
    default=0, type=int, help="Don't show debug info")



def perform_auth(opener):
    url = urllib.request.Request("https://" + args.domain + "/")
    url.add_header("User-Agent", USER_AGENT)
    url.add_header("Accept", ACCEPT)

    r = opener.open(url)

    login_url = r.url
    html_doc = r.read().decode('utf-8')
    logging.info(login_url)
    #logging.debug(html_doc)

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
    # new_url = re.search('window\.location\.replace\("([^"]+)"\)', html_doc).group(1)

    # logging.info(r.url)
    # #logging.debug(html_doc)

    # url = urllib.request.Request( urljoin(r.url, new_url))
    # url.add_header("User-Agent", USER_AGENT)
    # url.add_header("Accept", ACCEPT)

    # r = opener.open(url)

    # html_doc = r.read().decode('utf-8', 'ignore');

    main_url = r.url
    logging.info(r.url)
    #logging.debug(html_doc)

    return main_url

def put_file(opener, main_url, file, file_content):
    
    folder = args.dir + "/" + file
    folder_escaped = quote(folder, safe='')

    create_folder_url = urljoin(main_url, 
        "../filesharing/FileSharingExt/ShareAccessExt.dll?P=" + folder_escaped + "&overwrite=on")

    content_type, body = encode_multipart_formdata([
        ("remotefile", args.dir), 
        ("remotefilename", folder.replace('/', '\\').replace('\\\\', '//')), 
        ("overwrite", "on")
        ], [("Filedata", file, file_content)])
    
    url = urllib.request.Request(create_folder_url , body)

    url.add_header("User-Agent", USER_AGENT)
    url.add_header("Accept", ACCEPT)
    url.add_header("Content-Type", content_type)
    url.add_header("Content-Length", str(len(body)) )

    r = opener.open(url)
    html_doc = r.read().decode('utf-8', 'ignore');
    
    return html_doc
def create_folder(opener, main_url, folder_name):
    
    folder = args.dir + "/" + folder_name
    folder_escaped = quote(folder, safe='')

    create_folder_url = urljoin(main_url, "../filesharing/newfolder.asp?Folder=" + folder_escaped)

    content_type, body = encode_multipart_formdata([
        ("Filedata",folder_name), 
        ("remotefile",args.dir), 
        ("submit1", "Create Folder")], {})

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

def delete_file(opener, main_url, file):
    
    folder = args.dir + "/" + file
    folder_escaped = quote(folder, safe='')

    create_folder_url = urljoin(main_url, 
        "../filesharing/filelist.asp?S=" + folder_escaped + "&action=1&T=9")

    url = urllib.request.Request(create_folder_url)

    url.add_header("User-Agent", USER_AGENT)
    url.add_header("Accept", ACCEPT)

    r = opener.open(url)
    html_doc = r.read().decode('utf-8', 'ignore');

    return html_doc

def get_content(opener, main_url, file):
    
    folder = args.dir + "/" + file
    folder_escaped = quote(folder, safe='')

    create_folder_url = urljoin(main_url, "../filesharing/FileSharingExt/?OPEN&P=" + folder_escaped)

    url = urllib.request.Request(create_folder_url)

    url.add_header("User-Agent", USER_AGENT)
    url.add_header("Accept", ACCEPT)

    r = opener.open(url)
    doc = r.read()

    if doc.decode('cp437','ignore').find("content='0;URL=errorPage.asp?error=404") != -1:
        return None

    return doc

def gen_pck_uri(conn_token, line, index):
    return ".ms-ff-uag-tcp-data/%s-est/line-%s/pck-%s.bin" % (conn_token, line, str(index).zfill(8))


def mister_accept_client(client_reader, client_writer):
    if args.server:
        log.error("Something gone terribly wrong")
    log.info("New Connection")
    task = asyncio.Task(mister_handle_client(client_reader, client_writer))


async def mister_handle_client(client_reader, client_writer):

    conn_token = datetime.datetime.now().strftime("%H_%M-%d-%m-%Y_") + ('%08X' % random.randrange(16**8))

    create_folder(opener, main_url, ".ms-ff-uag-tcp-data/"+conn_token+"-est") # not like in spec
    create_folder(opener, main_url, ".ms-ff-uag-tcp-data/"+conn_token+"-est/line-mister") # not like in spec
    create_folder(opener, main_url, ".ms-ff-uag-tcp-data/"+conn_token+"-est/line-valet") # not like in spec

    put_file(opener, main_url, ".ms-ff-uag-tcp-data/to-connect/"+conn_token+".con", b'')

    task = asyncio.Task(mister_poll_valet(client_writer, conn_token, opener, main_url))
    
    index = 1
    while not client_reader.at_eof():
        log.debug("MISTER: waiting for read from client")

        data = await client_reader.read(BUFFER_SIZE)

        if client_reader.at_eof():
            data = b'!' + data
        else:
            data = b' ' + data

        log.debug("MISTER: got a read from client")
        log.debug('MISTER: sending "%r" (%d) to VALET' % (data, len(data)))

        put_file(opener, main_url, gen_pck_uri(conn_token, 'mister', index), data)
        index += 1

    log.warn('MISTER: reader closed')

async def mister_poll_valet(client_writer, conn_token,opener, main_url):

    index = 1
    while True:
        data = get_content(opener, main_url, gen_pck_uri(conn_token, 'valet', index))
        if data is not None:
            log.debug('MISTER: got data from VALET "%r" (%d b)' % (data, len(data)))
            log.debug('MISTER: relaying VALETS data')

            if data[0] == b'!'[0]:
                client_writer.write_eof()
                break
            else:
                client_writer.write(data[1:])
            index += 1
        else:
            log.debug("MISTER: no news from VALET")

        await asyncio.sleep(NEXT_TICK) 

    log.warn('MISTER: writer closed')


async def valet_poll_mister(writer, conn_token,opener, main_url):

    index = 1

    while True:
        data = get_content(opener, main_url, gen_pck_uri(conn_token, 'mister', index))

        if data is not None:
            log.debug('VALET: got data from MISTER "%r" (%d b)' % (data, len(data)))
            log.debug('VALET: relaying MISTERS data')

            if data[0] == b'!'[0]:
                writer.write_eof()
                break
            else:
                writer.write(data[1:])
            index += 1
        else:
            log.debug("VALET: no news from MISTER")
        
        await asyncio.sleep(NEXT_TICK)

    log.warn('VALET: writer closed')

async def valet_handle_server():
    # server is capable of only one connection at a time.

    while True:
        conn_token = ""
        while True:
            data = list_folder(opener, main_url, ".ms-ff-uag-tcp-data/to-connect/")
            if len(data):
                conn_token = data[0][1]
                delete_file(opener, main_url, ".ms-ff-uag-tcp-data/to-connect/"+conn_token)
                break
            await asyncio.sleep(NEXT_TICK)
            
        conn_token = conn_token.replace('.con', '')
        log.info("VALET: new connection from MISTER %s" % conn_token)
        
        reader, writer = await asyncio.open_connection("127.0.0.1", 8000)
        log.info("VALET: established server conn for %s" % conn_token)
        
        task = asyncio.Task(valet_poll_mister(writer, conn_token, opener, main_url))

        index = 1
        while not reader.at_eof():
            log.debug('VALET: waiting for a read from server')
            data = await reader.read(BUFFER_SIZE)

            if reader.at_eof():
                data = b'!' + data
            else:
                data = b' ' + data

            log.debug('VALET: got a read from server')
            log.debug('VALET: sending data to MISTER %r (%d b) ' % (data, len(data)))

            put_file(opener, main_url, gen_pck_uri(conn_token, 'valet', index), data)
            index += 1

        log.warn('VALET: reader closed')

    

if __name__ == '__main__':

    log = logging.getLogger("")
    formatter = logging.Formatter("%(asctime)s %(levelname)s " +
                                  "[%(module)s:%(lineno)d] %(message)s")
    # setup console logging

    args = ARGS.parse_args()
    with open(args.auth, 'r') as args.auth:
        auth_creds = args.auth.read()

    if args.quiet == 2:
        log.error('Logging error only')
        lvl = logging.ERROR
    elif args.quiet == 1:
        log.info('Logging info')
        lvl = logging.INFO
    elif args.quiet == 0:
        log.info('Logging debug')
        lvl = logging.DEBUG

    log.setLevel(lvl)
    ch = logging.StreamHandler()
    ch.setLevel(lvl)

    ch.setFormatter(formatter)
    log.addHandler(ch)
    

    ctx = ssl.create_default_context(cafile=args.cafile)
    cj = CookieJar(DefaultCookiePolicy(rfc2965=True, 
        strict_ns_domain=DefaultCookiePolicy.DomainStrict, blocked_domains=["ads.net", ".ads.net"]))
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), 
        urllib.request.HTTPCookieProcessor(cj))





    

    main_url = perform_auth(opener)

    loop = asyncio.get_event_loop()

    if signal is not None and sys.platform != 'win32':
        loop.add_signal_handler(signal.SIGINT, loop.stop)


    if args.server:
        f = asyncio.ensure_future(valet_handle_server())
    else:
        f = asyncio.start_server(mister_accept_client, host=None, port=8000)

    loop.run_until_complete(f)
    loop.run_forever()
    




    #create_folder(opener, main_url, 'testing-folders')
    #pprint(list_folder(opener, main_url, ''))
    #pprint(get_content(opener, main_url, 'ms-ff-uag-tcp.md'))
    #put_file(opener, main_url, '00000000.bin', b'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u2\r\n')
    #delete_file(opener, main_url, 'testing-132-folders')
    
