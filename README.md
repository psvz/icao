### ICAO Master List and Document Signing Certificates: finding, extraction, and trust chain verification
[International Civil Aviation Organization](https://en.wikipedia.org/wiki/International_Civil_Aviation_Organization) (ICAO) maintains a Public Key Infrastructure (PKI) suitable for independent verification of Machine Readable Travel Document (MRTD) i.e., [biometric passports and some national identity cards](https://en.wikipedia.org/wiki/Biometric_passport). Requirements the PKI aims at are set out in [Doc Series 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303). Essentially, it is two-level x509-certificates-based chain of trust, where an ICAO Master List holds root authorities and a document signing certificate list holds intermediaries.

Here, I offer a couple of scripts to locate and extract signing certificates from ICAO lists. In lieu of documentation an example with sufficient comments demonstrates intended workflow.

The scripts rely on `openssl` binary (version 3.0.2/Linux in tests). At the time of writing, pythonic closest `cryptography` module does not unfortunately cover sought functionality. Interestingly, `openssl` binary (version 1.1.1q/Windows) produces incorrect output at a step of `CMS` payload extraction, and the difference can be observed in number of bytes out. Hence, this solution is not Windows-portable.

The rationale behind this work was to identify the shortest auditable-yet-not personally identifiable proof-of-citizenship that can be independently verified. Biometric passports offer such proof in form of passport data' hash signed by a document signer (DS) certificate. Such **hash + the signature + DS fingerprint** (20 bytes) could represent our target sequence.

There are lots of DS's in circulation. A DS signing window would normally last three months. So, a cohort of passports (re)issued in a country every three months would have their associated cohort of DS's split by issuing department. Assuming 10 years' passport validity you could have an idea how many DS's should stay on the PKI.

DS's themselves are signed by Country Signing Certificate Authority (CSCA). Those are a handful of long players - members of ICAO master list. As they are trust anchors, they are a better fit in our *"independent verification"* bit, yet a worse choice for *"the shortest"* requirement, because our target sequence becomes **hash + its signature + full DS certificate**. Assuming compliance of the latter, it has embedded reference to CSCA (as we will see below).

In reality, a DS could go astray or not be having a reference to CSCA, which leave us with the "shortest" reliable option as **hash + its signature + full DS certificate + CSCA fingerprint**. Since biometric passports aren't ubiquitous at present, it is hard to envision anything on a scale that would utilize proposed approach, unless... Could a similar construct be good enough to replace physical documents altogether?
#### Getting hands dirty
Let's scan a British ePassport. A modern mobile phone has near-field communication (NFC) capability. The fanciest app I know of is [ReadID Me – Apps on Google Play](https://play.google.com/store/apps/details?id=nl.innovalor.nfciddocshowcase) - alternatively searchable in *App Store*. This app gives away both certificates of interest, however it holds back signatures of document data. There are a couple of projects aiming at reading API, they could help to get hold of the full dataset:

 - [AndyQ/NFCPassportReader: NFCPassportReader for iOS 13   
   (github.com)](https://github.com/AndyQ/NFCPassportReader)   
 - [PassID-Server/src/pymrtd at master · ZeroPass/PassID-Server   
   (github.com)](https://github.com/ZeroPass/PassID-Server/tree/master/src/pymrtd)

*ReadID Me* first scans MRZ to extract its digits that are used as a "password" to read NFC chip. This is an intentionally weak measure to just ensure the reading isn't done in pickpocket fashion. After the reading completes security tab of the app will contain document signing certificate's serial number and thumbprint (aka fingerprint).

In your clone of this repository, you may wish to update the following ICAO data files:
> icaopkd-001-dsccrl-005973.ldif
icaopkd-002-ml-000216.ldif

by solving CAPTCHA at the bottom of https://pkddownloadsg.icao.int/download

Although I use Serial in this example - I am just lucky: serials aren't unique and can easily produce irrelevant findings; instead, use fingerprint - punch in its characters without spaces. It works similar to `grep`:

    source bin/activate
    # ^ unless you prefer own environment
    python3 icao-dsprobe.py icaopkd-001-dsccrl-005973.ldif 1227817238
    
    ls DSCA/1227817238/
    01D889D96002C6A929D952148AD68956507975E9.pem  list
After thumbing through about 17 thousand certificates to the date, Serial #1227817238 returns only one match - with fingerprint in its name. Checking what it is:

    openssl x509 -text -noout -in DSCA/1227817238/01D889D96002C6A929D952148AD68956507975E9.pem
    
    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 1227817238 (0x492f0116)
            Signature Algorithm: ecdsa-with-SHA256
            Issuer: C = GB, O = UKKPA, CN = Country Signing Authority
            Validity
                Not Before: Feb  1 00:00:00 2022 GMT
                Not After : Jun  1 00:00:00 2033 GMT
            Subject: C = GB, O = HM Passport Office, OU = London, CN = Document Signing Key 37
            Subject Public Key Info:
                Public Key Algorithm: id-ecPublicKey
                    Public-Key: (256 bit)
                    pub:
                        04:1a:35:73:02:b5:21:4a:7d:b7:00:03:55:53:f8:
                        c3:7a:d4:f1:93:ca:b0:d8:4b:a6:4b:68:e4:ce:fa:
                        71:f7:08:4b:9e:e8:47:33:b9:f4:b6:03:b1:2d:94:
                        e9:47:bf:60:f9:2d:3b:19:47:7f:7d:e1:2d:e7:55:
                        00:fd:e2:2c:b2
                    Field Type: prime-field
                    Prime:
                        00:ff:ff:ff:ff:00:00:00:01:00:00:00:00:00:00:
                        00:00:00:00:00:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:
                        ff:ff:ff
                    A:
                        00:ff:ff:ff:ff:00:00:00:01:00:00:00:00:00:00:
                        00:00:00:00:00:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:
                        ff:ff:fc
                    B:
                        5a:c6:35:d8:aa:3a:93:e7:b3:eb:bd:55:76:98:86:
                        bc:65:1d:06:b0:cc:53:b0:f6:3b:ce:3c:3e:27:d2:
                        60:4b
                    Generator (uncompressed):
                        04:6b:17:d1:f2:e1:2c:42:47:f8:bc:e6:e5:63:a4:
                        40:f2:77:03:7d:81:2d:eb:33:a0:f4:a1:39:45:d8:
                        98:c2:96:4f:e3:42:e2:fe:1a:7f:9b:8e:e7:eb:4a:
                        7c:0f:9e:16:2b:ce:33:57:6b:31:5e:ce:cb:b6:40:
                        68:37:bf:51:f5
                    Order:
                        00:ff:ff:ff:ff:00:00:00:00:ff:ff:ff:ff:ff:ff:
                        ff:ff:bc:e6:fa:ad:a7:17:9e:84:f3:b9:ca:c2:fc:
                        63:25:51
                    Cofactor:  1 (0x1)
                    Seed:
                        c4:9d:36:08:86:e7:04:93:6a:66:78:e1:13:9d:26:
                        b7:81:9f:7e:90
            X509v3 extensions:
                X509v3 Subject Alternative Name:
                    email:document.technology@homeoffice.gov.uk, DirName:/L=GBR
                X509v3 Private Key Usage Period:
                    Not Before: Feb  1 00:00:00 2022 GMT, Not After: May  4 00:00:00 2022 GMT
                X509v3 Key Usage: critical
                    Digital Signature
                X509v3 Issuer Alternative Name:
                    DirName:/L=GBR, email:document.technology@hmpo.gov.uk, email:document.technology@homeoffice.gov.uk
                2.23.136.1.1.6.2:
                    0....1...P..PT
                X509v3 CRL Distribution Points:
                    Full Name:
                      URI:https://hmpo.gov.uk/csca/GBR.crl
                      URI:https://pkddownload1.icao.int/CRLs/GBR.crl
                X509v3 Authority Key Identifier:
                    49:9E:47:30:27:85:20:C5:7C:FC:11:80:24:E1:4C:15:62:A2:49:D6
                X509v3 Subject Key Identifier:
                    22:0A:C5:FA:B6:1E:8F:71:DD:F3:72:13:D7:D3:E8:CE:61:AA:0A:CA
        Signature Algorithm: ecdsa-with-SHA256
        Signature Value:
            30:64:02:30:18:c6:cb:e8:41:99:b7:d6:65:71:6c:4a:e1:7b:
            cb:b5:f9:bf:38:59:3b:80:1a:3d:5a:3d:3b:f7:f2:57:29:2f:
            6a:d9:30:07:5c:bf:08:f2:9e:f9:14:4d:55:c5:51:b7:02:30:
            60:01:19:66:dc:55:73:2b:10:41:b2:13:9e:8c:9a:0a:09:d4:
            95:48:7b:16:48:c5:f3:6b:8b:9b:62:19:01:f4:0c:77:b9:cd:
            5a:26:68:95:77:01:32:c1:6e:21:e2:29
There are three observations worth making. First of all, this certificate sports parametrized elliptic curve public key, good caption of why/what it is can be found in the last section of [Command Line Elliptic Curve Operations - OpenSSLWiki](https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations). Secondly, signature algorithm employs `sha256` to hash certificate's body - we will need this piece of information later. Finally, an extension line `X509v3 Authority Key Identifier` gives a unique reference to CSCA. And to get the latter we simply grep like so:

    python3 icao-mlprobe.py icaopkd-002-ml-000216.ldif 49:9E:47:30:27:85:20:C5:7C:FC:11:80:24:E1:4C:15:62:A2:49:D6
    
    ls CSCA/499E4730278520C57CFC118024E14C1562A249D6/
    0B18BB2A46781109AB8DB3C971F9ACB4FB64CE95.pem  8B685C03B33A0CFF4CBCE1324F1D4FC088173708.pem

Here we have two CSCA containing the same public key. The difference is that one CSCA is self-signed, while the other is cross signed (by a peer CSCA). Since the public key is the same, we can use either certificate to verify DSCA (Document signer) above. If curious, you can match CSCA fingerprints found by the script against the one stored in your passport's chip (reported by *ReadID Me* app).

Next, we verify that the document signer bears a valid CSCA signature, that is, the chain of trust propagates from the root (CSCA) to the intermediary (DSCA). For convenience we copy and rename certificates retrieved in the exercise above to

    example/ds.pem # document signer
    example/cs.pem # country signer
    cd example
The meaning of the following line options can be deduced from respective man pages e.g., `man openssl-asn1parse`. We use the fact that DS is signed with `sha256` in the last command:

    # extracting public key of the root authority :
    openssl x509 -in cs.pem -pubkey -noout >cs.pkey
    
    # extracting DS certificate without its signature (body) :
    openssl asn1parse -in ds.pem -strparse 4 -noout -out ds.body
    
    # extracting signature on the DS certificate (without its body) :
    openssl asn1parse -in ds.pem -strparse$(openssl asn1parse -in ds.pem |awk -F: '{x=$1}END{print x}') -out ds.sig
    
    # verifying the signature of the body with the public key :
    openssl dgst -sha256 -verify cs.pkey -signature ds.sig ds.body
    Verified OK
#### TODO
- Read NFC to extend the trust chain onto document's data e.g., DG1 (hashed MRZ)

Proud users of [D-Logic Readers](https://www.d-logic.com/nfc-rfid-reader-sdk/software/epassport-reading-machine-readable-travel-documents-mrtd/) or equivalent are sought - your help would be appreciated!
