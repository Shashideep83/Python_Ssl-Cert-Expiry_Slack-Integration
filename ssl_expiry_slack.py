
import ssl, socket
import pandas as pd
from datetime import datetime
import OpenSSL.crypto as crypto

hostname = ['google.co','expired.badssl.com']
datas = []
now = datetime.now()
#edit
for i in hostname:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with ctx.wrap_socket(socket.socket(), server_hostname = i) as s:
        s.connect((i, 443))
        cert = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,cert)
        commonName = x509.get_subject().CN
        notAfter = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        notBefore = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
        datas.append({
            "name": commonName, 
            "notAfter": notAfter,
            "notBefore": notBefore,
            "expired": (notAfter < now) or (notBefore > now)
        })

df = pd.DataFrame(datas) 

