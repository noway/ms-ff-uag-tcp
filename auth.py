import urllib.request, ssl
from http.cookiejar import CookieJar, DefaultCookiePolicy
import argparse
from bs4 import BeautifulSoup


ARGS = argparse.ArgumentParser(description="ms-ff-uag-tcp")


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

policy = DefaultCookiePolicy(rfc2965=True, strict_ns_domain=DefaultCookiePolicy.DomainStrict, blocked_domains=["ads.net", ".ads.net"])
cj = CookieJar(policy)
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(cj))
r = opener.open("https://" + args.domain + "/")


html_doc = r.read().decode('utf-8')

soup = BeautifulSoup(html_doc, 'html.parser')
uag_viewstate = soup.find(id="FormLogOn").find("input", {"name": "__VIEWSTATE"}).get("value")

print(uag_viewstate)

post_data = {
	"__VIEWSTATE": uag_viewstate,
	"FormLogOnUsernameTextBox": auth_creds.split("\n")[0],
	"FormLogOnPasswordTextBox": auth_creds.split("\n")[1],
	"FormLogOnRepositorySelectionList": "0",
	"FormLogOnLogOnCommand": "Log on",
}