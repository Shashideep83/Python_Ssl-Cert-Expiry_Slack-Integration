from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
import concurrent.futures
from socket import socket
from collections import namedtuple
import slack
from dateutil.relativedelta import relativedelta
from datetime import datetime,timedelta
from datetime import timedelta
from dateutil import tz
from datetime import datetime
import sys
import numpy as np
import io
from io import StringIO
import string
import pandas as pd
from pandas.compat import StringIO
from collections import Counter

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')

HOSTS = [
    ('google.com',443),
    ('facebook.com',443),
    ('stackoverflow.com',443),
]

def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer

def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def basic_info(hostinfo):
    s = '''{hostname}{peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    '''.format(
            hostname=hostinfo.hostname,
            peername=hostinfo.peername,
            commonname=get_common_name(hostinfo.cert),
            SAN=get_alt_names(hostinfo.cert),
            issuer=get_issuer(hostinfo.cert),
            notbefore=hostinfo.cert.not_valid_before,
            notafter=hostinfo.cert.not_valid_after
    )
   
    print(s)



orig_stdout = sys.stdout
f = open('outs.txt', 'w')
sys.stdout = f
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
    for hostinfo in e.map(lambda x: get_certificate(x[0], x[1]), HOSTS):
        basic_info(hostinfo)

sys.stdout = orig_stdout
f.close()           
f = open("outs.txt", "r")
a=(f.read())
data = a
a=(pd.read_csv(StringIO(data),
              header=None,
     #use a delimiter not present in the text file
     #forces pandas to read data into one column
              sep="/",
              names=['string'])
     #limit number of splits to 1
  .string.str.split(':',n=1,expand=True)
  .rename({0:'Name',1:'temp'},axis=1)
  .assign(temp = lambda x: np.where(x.Name.str.strip()
                             #look for string that ends 
                             #with a bracket
                              .str.match(r'(.*[)]$)'),
                              x.Name,
                              x.temp),
          Name = lambda x: x.Name.str.replace(r'(.*[)]$)','Name')
          )
   #remove whitespace
 .assign(Name = lambda x: x.Name.str.strip())
 .pivot(columns='Name',values='temp')
 .ffill()
 .dropna(how='any')
 .reset_index(drop=True)
 .rename_axis(None,axis=1)
 .filter(['Name','commonName','issuer','notBefore','notAfter'])      
  )

a=a.drop_duplicates(subset=['commonName'], keep='first')
today = datetime.today() + relativedelta(months=2) + relativedelta(days=2) # this date mactches google cert expiry date.Change Ac as per your req
#today = datetime.today() +  relativedelta(days=10)
#today = datetime.today()
month = today.strftime('%m')
year = today.strftime('%Y')
day = today.strftime('%d')


a['notBefore'] =  pd.to_datetime(a['notBefore'], format='%Y-%m-%d %H:%M:%S')
a['notAfter'] =  pd.to_datetime(a['notAfter'], format='%Y-%m-%d %H:%M:%S')
a = a.loc[(a['notAfter'] >= year +'-'+ month +'-'+day) & (a['notAfter'] <= year +'-'+ month +'-'+day + ' ' + '23:59:59')]
if len(a)==0:
    
    print("pass")
    
else:
    
    a['notAfter']=a['notAfter'].astype(str)
    a['notBefore']=a['notBefore'].astype(str)
    a['expiry']=(a['Name']+" SSL Cert Will Expire on "+a['notAfter'])
    a_list=a['expiry'].tolist()
    a_lists=[str(cell) for  cell in a_list]
    
    for abc in a_lists:
        client = slack.WebClient(token='SLACK_API_TOKEN') # add your slack token
        response = client.chat_postMessage(channel='#testos',text=abc)
        


