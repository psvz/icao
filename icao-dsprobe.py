# -*- coding: utf-8 -*-
"""
Created on Fri Oct 14 21:25:24 2022

@author: Vitaly Zuevsky

The latest collection of DSCA Certificates
at https://pkddownloadsg.icao.int/download
"""
import re
import sys

from pathlib    import Path
from os         import environ
from base64     import b64decode
from subprocess import Popen, PIPE

matched = 0
truncat = True
def procList():
    global matched, truncat

    der = b64decode(coded)

    proc = Popen(['openssl', 'x509', '-inform', 'der', '-noout', '-serial',\
                  '-fingerprint', '-issuer', '-subject', '-ext',\
                  'subjectKeyIdentifier,subjectAltName,authorityKeyIdentifier,issuerAltName'\
                 ], stdin=PIPE, stdout=PIPE, stderr=PIPE, env=environ)
    out, err = proc.communicate(der)

    if err: print(err.decode())
    else:
        grepable = ''.join(out.decode().split(':')).upper()
        decimal = str(int(re.search('SERIAL=(\S+)', grepable).group(1), base=16))
        grepable = decimal + '\n' + grepable
                
        if needle in grepable:

            matched += 1

            Path(f"DSCA/{needle}").mkdir(parents=True, exist_ok=True)
            if truncat: 
                truncat = False
                with open(f"DSCA/{needle}/list", 'w'): pass

            with open(f"DSCA/{needle}/list", 'a') as f:

                f.write(grepable + '\n')

            file = re.search('FINGERPRINT=(\w+)', grepable).group(1)

            proc = Popen(['openssl', 'x509', '-inform', 'der', '-outform', 'pem',\
                          '-out', f"DSCA/{needle}/{file}.pem"], env=environ,\
                          stdin=PIPE, stdout=PIPE, stderr=PIPE)
            out, err = proc.communicate(der)

            if err: print(err.decode())

#            1/0
# main :

if len(sys.argv) < 3:

    print(f"\nUsage: python3 {sys.argv[0]} <icaopkd-001-dsccrl-00XXXX.ldif> <needle>\n")
    sys.exit()

with open(sys.argv[1], "r") as f:

    lines = [line.rstrip() for line in f.readlines()]

needle =  ''.join(sys.argv[2].split(':')).upper()

count = 0
coded = ''
followUp = False
print()

for i in lines:

    if followUp:
        if i.startswith(' '): coded += i.split(' ')[-1]
        else:
            procList()

            count += 1
            coded = ''
            followUp = False
            print(f"\r{count}", end='')

    if i.startswith('userCertificate;binary:: '):

        coded = i.split(' ')[-1]
        followUp = True

print(f" inspected, {matched} certificate(s) dumped in DSCA/{needle} folder\n")
