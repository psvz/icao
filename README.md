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

> icaopkd-002-ml-000216.ldif

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
#### Understanding MRTD Secure Object (SO<sub>D</sub>) Structure
At a time of the writing [D-Logic Reader](https://www.d-logic.com/nfc-rfid-reader-sdk/software/epassport-reading-machine-readable-travel-documents-mrtd/) can read SOD from LDS v1.7 (see [Appendix D here](https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf)) but not from contemporary LDS v1.8 ([para 4.6.2](https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf)). Hence, an example in `sod-example` folder concerns the older LDS v1.7.

NFC read SOD object is present as binary file `sod`. We first strip SOD header with tag byte 0x77 to get more convenient PKCS7/CMS format:

    # strip SOD header :
    openssl asn1parse -inform der -in sod -strparse 4 -noout -out pkcs7
This format represents cryptographic message syntax (CMS), where the message..

    openssl cms -inform der -noverify -verify -in pkcs7 -out message
    openssl asn1parse -inform der -in message # datagroup hashes :
is a signed list of sha1 hashes for all data groups (DG) the document contains. The first command extracting the `message` binary file emits `CMS Verification successful`, confirming that the message is signed by the document signer (DS) certificate. We extract DS certificate and its parametrized public key like so:

    # extract document signer (ds), assuming no country signer (cs) in SOD :
    openssl pkcs7 -inform der -print_certs -in pkcs7 |grep -A99 CERT >ds.pem
    openssl x509 -in ds.pem -pubkey -noout >ds.pkey
Note, that a digest being signed is calculated over a structure called `SignedAttrs` from [CMS RFC](https://www.rfc-editor.org/rfc/rfc5652#section-5.4). Then, a signature of that structure is appended to the very end of `pkcs7` file, provided that `unsignedAttrs` optional field is missing as per Table 37 of [ICAO framework](https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf). Let's examine layout in question:

    openssl cms -cmsout -print -inform der -in pkcs7 |tail -28
-- out :

    digestAlgorithm:
      algorithm: sha1 (1.3.14.3.2.26)
      parameter: <ABSENT>
    signedAttrs:
        object: contentType (1.2.840.113549.1.9.3)
        set:
          OBJECT:undefined (2.23.136.1.1.1)

        object: signingTime (1.2.840.113549.1.9.5)
        set:
          UTCTIME:May 21 03:08:11 2015 GMT

        object: messageDigest (1.2.840.113549.1.9.4)
        set:
          OCTET STRING:
            0000 - fa f7 c7 ec 04 f8 f8 44-7b 5b 82 a5 ab   .......D{[...
            000d - de 6c c7 92 91 1b a9                     .l.....
    signatureAlgorithm:
      algorithm: ecdsa-with-SHA1 (1.2.840.10045.4.1)
      parameter: <ABSENT>
    signature:
      0000 - 30 44 02 20 4d b0 0b 91-68 57 93 51 0f 96 f6   0D. M...hW.Q...
      000f - a5 62 07 b7 00 c1 bc 30-27 d6 88 05 76 18 1c   .b.....0'...v..
      001e - e7 5d 6f 28 14 92 02 20-10 e4 1f 3d 02 e8 ed   .]o(... ...=...
      002d - 41 60 be 5a 57 6f 9f da-de bd 2e 93 5f 2d fe   A`.ZWo......_-.
      003c - 8a e6 9b af a2 02 10 58-7b 14                  .......X{.
    unsignedAttrs:
      <ABSENT>
Signed bytes here: OID `2.23.136.1.1.1`, which is undefined in CMS but defined as [LdsSecurityObject](https://oidref.com/2.23.136.1.1.1) from ICAO; time stamp when signing took place - here it predates passport issuance; message digest, algorithm of which is given right at the beginning of the snippet (sha1). And since we already have the "message" extracted, let's verify:

    sha1sum message
    faf7c7ec04f8f8447b5b82a5abde6cc792911ba9  message

Magic. Note, that `signatureAlgorithm` employs sha1 as well. Generally, hashing `message` and hashing `signedAttrs` could use different algorithms. Now, let's extract `signedAttrs` and `signature`. We do so by means of ASN1 parser. Although it is terser than the CMS parsing above, it provides byte offsets we need for extraction:

     openssl asn1parse -i -inform der -in pkcs7 |tail -18
     
     1137:d=5  hl=2 l=   7 cons:      SEQUENCE
     1139:d=6  hl=2 l=   5 prim:       OBJECT            :sha1
     1146:d=5  hl=2 l=  90 cons:      cont [ 0 ]
     1148:d=6  hl=2 l=  21 cons:       SEQUENCE
     1150:d=7  hl=2 l=   9 prim:        OBJECT            :contentType
     1161:d=7  hl=2 l=   8 cons:        SET
     1163:d=8  hl=2 l=   6 prim:         OBJECT            :2.23.136.1.1.1
     1171:d=6  hl=2 l=  28 cons:       SEQUENCE
     1173:d=7  hl=2 l=   9 prim:        OBJECT            :signingTime
     1184:d=7  hl=2 l=  15 cons:        SET
     1186:d=8  hl=2 l=  13 prim:         UTCTIME           :150521030811Z
     1201:d=6  hl=2 l=  35 cons:       SEQUENCE
     1203:d=7  hl=2 l=   9 prim:        OBJECT            :messageDigest
     1214:d=7  hl=2 l=  22 cons:        SET
     1216:d=8  hl=2 l=  20 prim:         OCTET STRING      [HEX DUMP]:FAF7C7EC04F8F8447B5B82A5ABDE6CC792911BA9
     1238:d=5  hl=2 l=   9 cons:      SEQUENCE
     1240:d=6  hl=2 l=   7 prim:       OBJECT            :ecdsa-with-SHA1
     1249:d=5  hl=2 l=  70 prim:      OCTET STRING      [HEX DUMP]:304402204DB00B91685793510F96F6A56207B700C1BC3027D6880576181CE75D6F281492022010E41F3D02E8ED4160BE5A576F9FDADEBD2E935F2DFE8AE69BAFA20210587B14

Note a block at offset 1146 and 90 bytes in length (`l= 90`). Parameter `d=` for depth shows level of indentation in pkcs7. Knowing these couple of things, we can be sure that the block is actually `signedAttrs`. Similarly, the last one is the sought signature. Extracting both:

    openssl asn1parse -inform der -in pkcs7 -strparse 1146 -out attrs
    openssl asn1parse -inform der -in pkcs7 -strparse$(openssl asn1parse -inform der -in pkcs7 |awk -F: '{x=$1}END{print x}') -out sod.sig

Changing the first byte of `attrs` extracted from 0xA0 to 0x31. Some [details on the trick](https://stackoverflow.com/a/24581628/2550808).

    # what we had :
    xxd attrs |head -1
    00000000: a05a 3015 0609 2a86 4886 f70d 0109 0331  .Z0...*.H......1
    
    xxd attrs >temp
    vi temp # first byte a0 -> 31
    cat temp |xxd -r >attrsExplicit
    
    # what we use :
    xxd attrsExplicit |head -1
    00000000: 315a 3015 0609 2a86 4886 f70d 0109 0331  1Z0...*.H......1

We can now verify the signature like so..

    openssl dgst -sha1 -verify ds.pkey -signature sod.sig attrsExplicit
    Verified OK
However, we'd better compress it all down to a hash being signed, that is

    sha1sum attrsExplicit |awk '{print$1}' |xxd -r -ps >sod.hash
Time to recap. Passport's DG1 (ordinary passport data) and DG2 (face-photo file) are both hashed, and the hashes are injected in a `message` (hash algorithm is there too). The `message` is hashed, and the hash is injected into a `signedAttrs` (the algo is in pkcs7). The `signedAttrs` is hashed (the algo is in pkcs7) and we have it in `sod.hash` file (20 bytes' token in case of sha1).

The token is uniquely derived from some personal data. As such, it can serve as a personal identifier, albeit with multiple levels of indirection. The token is non-fudgeable (aka NFT) in a sense that it is signed by a State (as opposed to recording on a decentralized blockchain), so it cannot be altered if accompanied by the signature (70 bytes in `sod.sig` file) and the final ingredient - reference to the public key - another 20 bytes of `Subject Key Identifier` from the signing certificate:

    openssl x509 -in ds.pem -noout -text |grep -A1 X509
    
            X509v3 extensions:
                X509v3 Key Usage: critical
                    Digital Signature
                X509v3 Subject Key Identifier:
                    07:10:06:8A:48:58:FA:04:58:08:8C:47:67:99:BA:1D:5F:EB:2C:3F
                X509v3 Authority Key Identifier:
                    56:59:99:89:A1:CC:1C:13:D3:9F:BC:B0:C8:77:00:38:50:33:A5:33

As all certificates are supposed to be publicly available at ICAO PKI, anyone could download this certificate, extract public key, and verify the "NFT" like so:

    openssl pkeyutl -verify -sigfile sod.sig -pubin -inkey ds.pkey -in sod.hash
    Signature Verified Successfully

The problem is that this particular document signer isn't on ICAO PKI:

    python3 icao-dsprobe.py icaopkd-001-dsccrl-005973.ldif 07:10:06:8A:48:58:FA:04:58:08:8C:47:67:99:BA:1D:5F:EB:2C:3F
    
    17763 inspected, 0 certificate(s) dumped in DSCA/0710068A4858FA0458088C476799BA1D5FEB2C3F folder

Authority certificate, on the other hand, is on ICAO Master list. So, our "NFT" would have to comprise 20 bytes token + 70 bytes signature + 844 byes document signer (whole certificate):

    openssl x509 -in ds.pem -outform der -out ds.der

Not very elegant.
#### Future?
It is interesting to notice that conventional identification relies on subjective (latterly AI-based) matching between a state issued document and a personal look (generally - biometric scans). That would be comparable if not inferior to a cryptographic ["limited knowledge" proof](https://en.wikipedia.org/wiki/Zero-knowledge_proof) of possession of a signed message (e.g., State-signed identifier). The latter would not require biometric scans, however, which makes it suitable for paperless remote identification. An abstract problem statement - [here](https://crypto.stackexchange.com/q/102705/104362).
