# -*- coding: utf-8 -*-
"""
Created on Fri Oct 14 21:25:24 2022

@author: Vitaly Zuevsky

The latest collection of CSCA Master Lists
at https://pkddownloadsg.icao.int/download
"""
import re
import sys
import asn1tools
asn1 = asn1tools.compile_files(['PKIX1Explicit88.asn', 'master.asn'])

from pathlib    import Path
from os         import environ
from base64     import b64decode
from subprocess import Popen, PIPE

needle = ''
neelist = []
def procList():

    pkcs7container = b64decode(coded)

    proc = Popen(['openssl', 'cms', '-inform', 'der', '-noverify', '-verify'],\
                 stdin=PIPE, stdout=PIPE, stderr=PIPE, env=environ)
    out, err = proc.communicate(pkcs7container)
    
    verr = err.decode()

    # no pythonic equivalent of this data moving from the contaner - ugh :
    proc = Popen(['openssl', 'cms', '-inform', 'der', '-noverify', '-verify', '-nosigs'],\
                 stdin=PIPE, stdout=PIPE, stderr=PIPE, env=environ)
    out, err = proc.communicate(pkcs7container)
    
    if out:

        diag =\
        f"CMS extraction: {len(pkcs7container)} bytes in - {len(out)} bytes out\n{verr}"

        print(diag, end='')
        ml = asn1.decode('CscaMasterList', out)

        count = f"{len(ml['certList'])} certificates are on the list..."
        print(count)
        
        with open(f"CSCA/{country}list", 'w') as f:

            f.write(dn + '\n' + diag + count + '\n\n')

        for i in ml['certList']:

            cert = asn1.encode('Certificate', i)
            sn = str(i['tbsCertificate']['serialNumber']) # decimal

            proc = Popen(['openssl', 'x509', '-inform', 'der', '-noout', '-serial',\
                          '-fingerprint', '-issuer', '-subject', '-ext',\
                          'subjectKeyIdentifier,subjectAltName,authorityKeyIdentifier,issuerAltName'\
                         ], stdin=PIPE, stdout=PIPE, stderr=PIPE, env=environ)
            out, err = proc.communicate(cert)

            if err: print(err.decode())
            else:
                grepable = sn + '\n' + ''.join(out.decode().split(':')).upper()
                with open(f"CSCA/{country}list", 'a') as f:

                    f.write(grepable + '\n')
                
                # needle for dumping certs :
                if needle and needle in grepable:

                    Path(f"CSCA/{needle}").mkdir(exist_ok=True)
                    file = re.search('FINGERPRINT=(\w+)', grepable).group(1)

                    proc = Popen(['openssl', 'x509', '-inform', 'der', '-outform', 'pem',\
                                  '-out', f"CSCA/{needle}/{file}.pem"], env=environ,\
                                 stdin=PIPE, stdout=PIPE, stderr=PIPE)
                    out, err = proc.communicate(cert)

                    if err: print(err.decode())

                    neelist.append(f"{country}")
#    1/0
# main :

if len(sys.argv) < 2:

    print(f"\nUsage: python3 {sys.argv[0]} <icaopkd-002-ml-00XXXX.ldif> [needle]\n")
    sys.exit()

with open(sys.argv[1], "r") as f:

    lines = [line.rstrip() for line in f.readlines()]

Path('CSCA').mkdir(exist_ok=True)

if len(sys.argv) > 2:

    needle =  ''.join(sys.argv[2].split(':')).upper()

coded = ''
followUp = False

for i in lines:

    if followUp:
        if i.startswith(' '): coded += i.split(' ')[-1]
        else:
            procList()

            coded = ''
            followUp = False


    if i.startswith('dn: '): dn = i
    if i.startswith('CscaMasterListData:: '):

        print(f"\nProcessing: {dn}")
        country = re.search('=([A-Z][A-Z])', dn).group(1)
        coded = i.split(' ')[-1]
        followUp = True

if neelist:

    print(f"\n{needle} seen in the lists from:\n{neelist}")

print()
