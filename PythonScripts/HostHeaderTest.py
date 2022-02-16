import argparse
import textwrap
import requests
import re

red = "\033[31m"
nul = "\033[0m"

evil_string = "evil-site.com"

def is_url(x):
    return bool(re.match(
        r"(https?|ftp)://" # protocol
        r"(\w+(\-\w+)*\.)?" # host (optional)
        r"((\w+(\-\w+)*)\.(\w+))" # domain
        r"(\.\w+)*" # top-level domain (optional, can have > 1)
        r"([\w\-\._\~/]*)*(?<!\.)" # path, params, anchors, etc. (optional)
    , x))

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--host', required=True)
args = vars(parser.parse_args())
print(args)
url = args['host']

headers = {'Content-Type': 'application/json; charset=utf-8','Host': evil_string,'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0',}

def print_roundtrip(response, *args, **kwargs):
    format_headers = lambda d: '\n'.join(f'{k}: {v}' for k, v in d.items())
    output = textwrap.dedent('''
        ---------------- request ----------------
        {req.method} {req.url}
        {reqhdrs}

        {req.body}
        ---------------- response ----------------
        {res.status_code} {res.reason} {res.url}
        {reshdrs}

        {res.text}
    ''').format(
        req=response.request, 
        res=response, 
        reqhdrs=format_headers(response.request.headers), 
        reshdrs=format_headers(response.headers), 
    )
    print(output)

requests.get(url,headers=headers,hooks={'response': print_roundtrip},allow_redirects=False)



