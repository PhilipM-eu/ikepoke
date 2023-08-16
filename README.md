# ikepoke
Ikepoke is a security testing tool for IKE endpoints, which was developed as part of a masters thesis. 
Ikepoke's focus lies on IKEv2, but it does support sending IKEv1 main mode and aggressive mode phase 1 packets.
Its main purpose is to perform (fast) scans on targets to find out which IKE transforms they offer for both IKEv1 and IKEv2. For IKEv2 it offers the testing  whether a user supplied pre-shared key is accepted by the target. Additionally to performing scans, ikepoke can also send single user defined transform proposals.
As a proof-of-concept the exploitation of two denial-of-service vulnerabilities (CVE-2023-23009 and CVE-2023-30570) of the open source IPSec solution libreswan is included . 
## Disclaimer
Ikepoke is meant to be used ONLY for legal security research and legal security testing (e.g. during a penetration test). Only use this tool if you have the EXPLICIT permission to attack the target or if you are the owner of the target. Any other use will get you into legal trouble with the relevant authorities. 

## Installation/Compilation
### Prerequisites
1. Working go installation (see https://go.dev/doc/install)
2. Network access to fetch a package not included in the go standard library
### Compilation from source and test run

`git clone https://github.com/PhilipM-eu/ikepoke.git`

`cd ikepoke && mkdir build`

`go build -o ./build/ikepoke main.go`

`cd build`

`./ikepoke --help`


## Features - What can ikepoke do?
- Discover whether a given target is a actually an IKE endpoint
- take single targets over the command line parameters or multiple targets as a file
- Perform single or multi threaded scans on IKE targets to discover the cryptographic transforms they support for security associations
- Send arbitrary(user defined) transform proposals
- Test user supplied pre-shared keys for validity on IKEv2 targets
- Exploit the CVE-2023-23009 vulnerability on a vulnerable libreswan target
- Exploit the CVE-2023-30570 vulnerability on a vulnerable libreswan target
## What can ikepoke not (yet) do?
- test IKE over any other protocol than UDP
- bruteforce pre-shared keys in either IKEv1 or IKEv2
- Support certificate based authentication
- Fingerprint IKE targets
- Support IKEv1 authentication (neither main nor aggressive mode)
- Support encryption algorithms other than AES-GCM for authentication
- Support a way for the user to slow down the scan (i.e. a sleep between sending packets)
- Output scan results in a file format such as CSV, XML or JSON
- Exploit any other IKE implementation vulnerability
## Examples
Setting the source IP with `-s` is necessary for anything that is not meant to go to localhost. Per scan it is only possible to scan IKEv1 main mode or IKEv1 aggressive mode. If both are meant to be tested, perform two scans.


Perform a full transform single threaded scan in both IKEv1 main mode and IKEv2 on the targets in the file targets.txt:

`ikepoke -s 192.168.1.1 -f targets.txt --scan --scanmode full --ikev1 --ikev2`

Perform a limited transform multi threaded scan in both IKEv1 aggressive mode and IKEv2 on the targets in the file targets.txt:

`ikepoke -s 192.168.1.1 -f targets.txt --scan --scanmode common --ikev1 --aggressive --ikev2 --worker 10`

Send out a single transform proposal to the target 192.168.1.113:500 without performing discovery first:

`ikepoke -s 192.168.1.1 -t 192.168.1.113:500 --ikev2 -transformv2 7/256,2,1,14 --single --nd`

Try to exploit CVE-2023-23009 on a libreswan target with the PSK "1234":

`ikepoke -s 192.168.1.1 -t 192.168.1.113:500 --ikev2 --ikev2dos --psk 1234`

Try to exploit CVE-2023-30570 on a libreswan target:

`ikepoke -s 192.168.1.1 -t 192.168.1.113:500 --ikev1 --ikev1dos`

## Planned features 
(not necessarily in this order)
- Support certificate based authentication
- Fingerprint IKE targets
- Support IKEv1 authentication
- Support other encryption algorithms for authentication
- Support a way for the user to slow down the scan (i.e. a sleep between sending packets)
- Output scan results in a file format such as CSV, XML or JSON 
