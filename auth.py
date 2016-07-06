#!/usr/bin/env python3

import asyncio

from collections import OrderedDict
from requests_toolbelt import MultipartEncoder

try:
    import signal
except ImportError:
    signal = None
import logging
    
import urllib.request, ssl
from urllib.parse import urljoin, quote
from http.cookiejar import CookieJar, DefaultCookiePolicy

from bs4 import BeautifulSoup

import re
import sys
import argparse
from pprint import pprint

import datetime
import random

log = logging.getLogger(__name__)
uag_session = None

BUFFER_SIZE = 1024*768
NEXT_TICK = 0.001 


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
        
class UAGSession:
    """Class for working with UAG"""

    opener = None
    home_url = None

    def __init__(self, opener):
        # super(UAGSession, self).__init__()
        self.opener = opener


    def perform_auth(self):
        url = urllib.request.Request("https://" + args.domain + "/")
        url.add_header("User-Agent", USER_AGENT)
        url.add_header("Accept", ACCEPT)

        r = self.opener.open(url)

        login_url = r.url
        html_doc = r.read().decode('utf-8')
        logging.info(login_url)
        # logging.debug(html_doc)

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

        r = self.opener.open(url)

        html_doc = r.read().decode('utf-8', 'ignore');
        # new_url = re.search('window\.location\.replace\("([^"]+)"\)', html_doc).group(1)

        # logging.info(r.url)
        # #logging.debug(html_doc)

        # url = urllib.request.Request( urljoin(r.url, new_url))
        # url.add_header("User-Agent", USER_AGENT)
        # url.add_header("Accept", ACCEPT)

        # r = self.opener.open(url)

        # html_doc = r.read().decode('utf-8', 'ignore');

        main_url = r.url
        logging.info(r.url)
        #logging.debug(html_doc)

        self.main_url = main_url


    def put_file(self, file, file_content):
        
        folder = args.dir + "/" + file
        folder_escaped = quote(folder, safe='')

        create_folder_url = urljoin(self.main_url, 
            "../filesharing/FileSharingExt/ShareAccessExt.dll?P=" + folder_escaped + "&overwrite=on")

        files = OrderedDict([
            ("Filedata", (file, file_content, 'application/octet-stream') ),
            ("remotefile", args.dir), 
            ("remotefilename", folder.replace('/', '\\').replace('\\\\', '//') ), 
            ("overwrite", "on"),
        ])

        encoder = MultipartEncoder(files)
        body2 = encoder.to_string()

        url = urllib.request.Request(create_folder_url , body2)

        url.add_header("User-Agent", USER_AGENT)
        url.add_header("Accept", ACCEPT)
        url.add_header("Content-Type", encoder.content_type)
        url.add_header("Content-Length", str(len(body2)) )

        r = self.opener.open(url)
        html_doc = r.read().decode('utf-8', 'ignore');
        
        return html_doc

    def create_folder(self, directory):
        
        folder = args.dir + "/" + directory
        folder_escaped = quote(folder, safe='')

        create_folder_url = urljoin(self.main_url, "../filesharing/newfolder.asp?Folder=" + folder_escaped)

        files = OrderedDict([
            ("Filedata", directory ),
            ("remotefile", args.dir), 
            ("submit1", "Create Folder"),
        ])

        encoder = MultipartEncoder(files)
        body2 = encoder.to_string()

        url = urllib.request.Request(create_folder_url , body2)

        url.add_header("User-Agent", USER_AGENT)
        url.add_header("Accept", ACCEPT)
        url.add_header("Content-Type", encoder.content_type)
        url.add_header("Content-Length", str(len(body2)) )

        r = self.opener.open(url)
        html_doc = r.read().decode('utf-8', 'ignore');

        return html_doc


    def list_folder(self, directory):
        
        folder = args.dir + "/" + directory
        folder_escaped = quote(folder, safe='')

        create_folder_url = urljoin(self.main_url, "../filesharing/filelist.asp?S=" + folder_escaped + "&T=9")

        url = urllib.request.Request(create_folder_url)

        url.add_header("User-Agent", USER_AGENT)
        url.add_header("Accept", ACCEPT)

        r = self.opener.open(url)
        html_doc = r.read().decode('utf-8', 'ignore');


        return_arr = []
        try:
            soup = BeautifulSoup(html_doc, 'html.parser')
            file_nodes = soup.find(id="fileListTable").find("tbody").find_all("label")
            for i in file_nodes:
                if i.get("onmousedown").find('isFile = true') != -1:
                    isFile = True
                else:
                    isFile = False

                return_arr.append((isFile, i.find('nobr').text))
        except Exception:
            return_arr = None
        return return_arr

    def delete_file(self, file):
        
        folder = args.dir + "/" + file
        folder_escaped = quote(folder, safe='')

        create_folder_url = urljoin(self.main_url, 
            "../filesharing/filelist.asp?S=" + folder_escaped + "&action=1&T=9")

        url = urllib.request.Request(create_folder_url)

        url.add_header("User-Agent", USER_AGENT)
        url.add_header("Accept", ACCEPT)

        r = self.opener.open(url)
        html_doc = r.read().decode('utf-8', 'ignore');

        return html_doc

    def get_content(self, file):
        
        folder = args.dir + "/" + file
        folder_escaped = quote(folder, safe='')

        create_folder_url = urljoin(self.main_url, "../filesharing/FileSharingExt/?OPEN&P=" + folder_escaped)

        url = urllib.request.Request(create_folder_url)

        url.add_header("User-Agent", USER_AGENT)
        url.add_header("Accept", ACCEPT)

        r = self.opener.open(url)
        doc = r.read(100)

        if doc.decode('cp437','ignore').find("content='0;URL=errorPage.asp?error=404") != -1:
            return (None,None,None)

        return (doc, r, file)


        
def gen_pck_uri(conn_token, line, index):
    return ".ms-ff-uag-tcp-data/%s-est/line-%s/pck-%s.bin" % (conn_token, line, str(index).zfill(8))


async def dump_reader_to_writer(reader, writer):
    doc = await loop.run_in_executor(None, reader.read, 16*1024)
    writer.write(doc)

    while doc:
        doc = await loop.run_in_executor(None, reader.read, 16*1024)
        writer.write(doc)

async def make_gc(opener, url):
    await loop.run_in_executor(None, uag_session.delete_file, url)


def mister_accept_client(client_reader, client_writer):
    if args.server:
        log.error("Something gone terribly wrong")
    log.info("New Connection")
    task = asyncio.Task(mister_handle_client(client_reader, client_writer))






async def actor_pipe_socket_uag(actor, conn_token, socket_reader):

    index = 1
    sent_data = {}
    kept_data = {}

    while not socket_reader.at_eof():

        while sum(kept_data.values()) > 4 * 1024*1024:

            files = await loop.run_in_executor(None, 
                uag_session.list_folder, ".ms-ff-uag-tcp-data/"+conn_token+"-est/line-"+actor)

            new_sent = {}

            for i in files:
                key = int(i[1].replace('pck-','').replace('.bin',''))
                new_sent[key] = sent_data[key]

            kept_data = new_sent

            if sum(kept_data.values()) > 2 * 1024*1024:
                await asyncio.sleep(3.2)


        log.debug(actor+': waiting for a read from server')

        data = await socket_reader.read(BUFFER_SIZE)

        if socket_reader.at_eof():
            data = b'!' + data
        else:
            data = b' ' + data

        log.debug(actor+': got a read from server')
        log.debug(actor+': sending data to MISTER %r (%d b) ' % (data, len(data)))

        asyncio.ensure_future(loop.run_in_executor(None, 
            uag_session.put_file, gen_pck_uri(conn_token, actor, index), data))
        
        log.info(actor+': putting index %d as %d b' % (index, len(data)))

        kept_data[index] = len(data)
        sent_data[index] = len(data)

        index += 1

    log.warn(actor+': reader closed')

    

async def actor_pipe_uag_socket(actor, conn_token, socket_writer):
    # TODO: what if listing does not return the packet which sequentially goes next? 

    read_packets = {}
    other = "mister" if actor == "valet" else "valet"

    listing_task = asyncio.ensure_future(loop.run_in_executor(
        None, uag_session.list_folder, ".ms-ff-uag-tcp-data/"+conn_token+"-est/line-"+actor))
    
    while True:

        log.debug(other+': awaiting for packet listing')

        listing = await listing_task or []

        # listing = listing or []

        log.debug(other+': awaited')

        tasks = []

        # We are relying here on UAG alphanumerical sorting
        for i in listing:
            if i[1] not in read_packets:
                read_packets[i[1]] = True

                task = asyncio.ensure_future(loop.run_in_executor(None, uag_session.get_content, 
                    ".ms-ff-uag-tcp-data/"+conn_token+"-est/line-"+actor+"/"+i[1]))

                tasks.append(task)

        if len(tasks):
            log.debug(other+': awaiting for first read from UAG')
            await asyncio.wait([tasks[0]], timeout=None)
        else:
            log.debug(other+': empty pck queue')
        
        listing_task = asyncio.ensure_future(loop.run_in_executor(
            None, uag_session.list_folder, ".ms-ff-uag-tcp-data/"+conn_token+"-est/line-"+actor))

        log.debug(other+": starting ordered parallelism")
        for task in tasks:
            data, r, url = await task
            
            log.debug(other+': got data from VALET "%r" (%d b)' % (data, len(data)))
            log.debug(other+': relaying VALETS data')

            if data[0] == b'!'[0]:
                socket_writer.write_eof()
                break
            else:
                socket_writer.write(data[1:])
                await dump_reader_to_writer(r, socket_writer)
    
            asyncio.ensure_future(loop.run_in_executor(None, uag_session.delete_file, url))

        await asyncio.sleep(NEXT_TICK) 

    log.warn(other+': writer closed')






async def mister_handle_client(client_reader, client_writer):

    conn_token = datetime.datetime.now().strftime("%H_%M-%d-%m-%Y_") + ('%08X' % random.randrange(16**8))

    uag_session.put_file(".ms-ff-uag-tcp-data/to-connect/"+conn_token+".con", b'')

    task = asyncio.Task(mister_poll_valet(client_writer, conn_token, opener))


    while True:
        data = uag_session.list_folder(".ms-ff-uag-tcp-data/"+conn_token+"-est/")

        if data is None:
            log.info("data is None")
            await asyncio.sleep(NEXT_TICK)
            continue
        
        # pprint(data)
        
        if (False, "line-mister") in data:
            pprint(data)
            log.info("connection established!!")
            break
        else:
            log.info("waiting to ack from server")

        await asyncio.sleep(NEXT_TICK)
    
    await actor_pipe_socket_uag("mister", conn_token, client_reader)


async def mister_poll_valet(client_writer, conn_token, opener):

    await actor_pipe_uag_socket('valet', conn_token, client_writer)


async def valet_poll_mister(writer, conn_token,opener):

    await actor_pipe_uag_socket('mister', conn_token, writer)


async def valet_handle_server():
    # server is capable of only one connection at a time.

    while True:

        conn_token = ""
        while True:
            data = uag_session.list_folder(".ms-ff-uag-tcp-data/to-connect/")
            if len(data):
                conn_token = data[0][1].replace('.con', '')
                uag_session.create_folder(".ms-ff-uag-tcp-data/"+conn_token+"-est") # not like in spec
                uag_session.create_folder(".ms-ff-uag-tcp-data/"+conn_token+"-est/line-mister") # not like in spec
                uag_session.create_folder(".ms-ff-uag-tcp-data/"+conn_token+"-est/line-valet") # not like in spec
                uag_session.delete_file(".ms-ff-uag-tcp-data/to-connect/"+conn_token+".con")
                break
            await asyncio.sleep(NEXT_TICK)

        log.info("VALET: new connection from MISTER %s" % conn_token)
        
        reader, writer = await asyncio.open_connection("127.0.0.1", 22)
        log.info("VALET: established server conn for %s" % conn_token)
        
        task = asyncio.Task(valet_poll_mister(writer, conn_token, opener))

        await actor_pipe_socket_uag("valet", conn_token, reader)

    

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





    
    uag_session = UAGSession(opener)
    uag_session.perform_auth()
    #main_url = perform_auth(opener)

    loop = asyncio.get_event_loop()

    if signal is not None and sys.platform != 'win32':
        loop.add_signal_handler(signal.SIGINT, loop.stop)


    if args.server:
        f = asyncio.ensure_future(valet_handle_server())
    else:
        f = asyncio.start_server(mister_accept_client, host=None, port=8000)

    loop.run_until_complete(f)
    loop.run_forever()
    



    # Unit tests would be of use
    #create_folder(opener, main_url, 'testing-folders')
    #pprint(list_folder(opener, main_url, ''))
    #pprint(get_content(opener, main_url, 'ms-ff-uag-tcp.md'))
    #put_file(opener, main_url, '00000000.bin', b'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u2\r\n')
    #delete_file(opener, main_url, 'testing-132-folders')
    
