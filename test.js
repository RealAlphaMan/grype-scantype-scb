const result = `{
    "matches": [
       {
           "vulnerability": {
            "id": "CVE-2013-4235",
            "dataSource": "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2013-4235",
            "namespace": "ubuntu:20.04",
            "severity": "Low",
            "urls": [
             "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2013-4235"
            ],
            "cvss": [],
            "fix": {
             "versions": [],
             "state": "not-fixed"
            },
            "advisories": []
           },
           "relatedVulnerabilities": [
            {
             "id": "CVE-2013-4235",
             "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2013-4235",
             "namespace": "nvd",
             "severity": "Medium",
             "urls": [
              "https://security-tracker.debian.org/tracker/CVE-2013-4235",
              "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4235",
              "https://access.redhat.com/security/cve/cve-2013-4235",
              "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E"
             ],
             "description": "shadow: TOCTOU (time-of-check time-of-use) race condition when copying and removing directory trees",
             "cvss": [
              {
               "version": "2.0",
               "vector": "AV:L/AC:M/Au:N/C:N/I:P/A:P",
               "metrics": {
                "baseScore": 3.3,
                "exploitabilityScore": 3.4,
                "impactScore": 4.9
               },
               "vendorMetadata": {}
              },
              {
               "version": "3.1",
               "vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
               "metrics": {
                "baseScore": 4.7,
                "exploitabilityScore": 1,
                "impactScore": 3.6
               },
               "vendorMetadata": {}
              }
             ]
            }
           ],
           "matchDetails": [
            {
             "type": "exact-indirect-match",
             "matcher": "dpkg-matcher",
             "searchedBy": {
              "distro": {
               "type": "ubuntu",
               "version": "20.04"
              },
              "namespace": "ubuntu:20.04",
              "package": {
               "name": "shadow",
               "version": "1:4.8.1-1ubuntu5.20.04.1"
              }
             },
             "found": {
              "versionConstraint": "none (deb)"
             }
            }
           ],
           "artifact": {
            "name": "login",
            "version": "1:4.8.1-1ubuntu5.20.04.1",
            "type": "deb",
            "locations": [
             {
              "path": "/usr/share/doc/login/copyright",
              "layerID": "sha256:ddb7bdf7b2c1eeebb730b55edf47be34b8fccf76d21bf173b948db9d2199802d"
             },
             {
              "path": "/var/lib/dpkg/info/login.conffiles",
              "layerID": "sha256:ddb7bdf7b2c1eeebb730b55edf47be34b8fccf76d21bf173b948db9d2199802d"
             },
             {
              "path": "/var/lib/dpkg/info/login.md5sums",
              "layerID": "sha256:ddb7bdf7b2c1eeebb730b55edf47be34b8fccf76d21bf173b948db9d2199802d"
             },
             {
              "path": "/var/lib/dpkg/status",
              "layerID": "sha256:ddb7bdf7b2c1eeebb730b55edf47be34b8fccf76d21bf173b948db9d2199802d"
             }
            ],
            "language": "",
            "licenses": [
             "GPL-2"
            ],
            "cpes": [
             "cpe:2.3:a:login:login:1:4.8.1-1ubuntu5.20.04.1:*:*:*:*:*:*:*"
            ],
            "purl": "pkg:deb/ubuntu/login@1:4.8.1-1ubuntu5.20.04.1?arch=arm64&upstream=shadow&distro=ubuntu-20.04",
            "upstreams": [
             {
              "name": "shadow"
             }
            ]
           }
          },
          {
            "vulnerability": {
             "id": "CVE-2013-4235",
             "dataSource": "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2013-4235",
             "namespace": "ubuntu:20.04",
             "severity": "Low",
             "urls": [
              "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2013-4235"
             ],
             "cvss": [],
             "fix": {
              "versions": [],
              "state": "not-fixed"
             },
             "advisories": []
            },
            "relatedVulnerabilities": [
             {
              "id": "CVE-2013-4235",
              "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2013-4235",
              "namespace": "nvd",
              "severity": "Medium",
              "urls": [
               "https://security-tracker.debian.org/tracker/CVE-2013-4235",
               "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4235",
               "https://access.redhat.com/security/cve/cve-2013-4235",
               "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E"
              ],
              "description": "shadow: TOCTOU (time-of-check time-of-use) race condition when copying and removing directory trees",
              "cvss": [
               {
                "version": "2.0",
                "vector": "AV:L/AC:M/Au:N/C:N/I:P/A:P",
                "metrics": {
                 "baseScore": 3.3,
                 "exploitabilityScore": 3.4,
                 "impactScore": 4.9
                },
                "vendorMetadata": {}
               },
               {
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
                "metrics": {
                 "baseScore": 4.7,
                 "exploitabilityScore": 1,
                 "impactScore": 3.6
                },
                "vendorMetadata": {}
               }
              ]
             }
            ],
            "matchDetails": [
             {
              "type": "exact-indirect-match",
              "matcher": "dpkg-matcher",
              "searchedBy": {
               "distro": {
                "type": "ubuntu",
                "version": "20.04"
               },
               "namespace": "ubuntu:20.04",
               "package": {
                "name": "shadow",
                "version": "1:4.8.1-1ubuntu5.20.04.1"
               }
              },
              "found": {
               "versionConstraint": "none (deb)"
              }
             }
            ],
            "artifact": {
             "name": "passwd",
             "version": "1:4.8.1-1ubuntu5.20.04.1",
             "type": "deb",
             "locations": [
              {
               "path": "/usr/share/doc/passwd/copyright",
               "layerID": "sha256:ddb7bdf7b2c1eeebb730b55edf47be34b8fccf76d21bf173b948db9d2199802d"
              },
              {
               "path": "/var/lib/dpkg/info/passwd.conffiles",
               "layerID": "sha256:ddb7bdf7b2c1eeebb730b55edf47be34b8fccf76d21bf173b948db9d2199802d"
              },
              {
               "path": "/var/lib/dpkg/info/passwd.md5sums",
               "layerID": "sha256:ddb7bdf7b2c1eeebb730b55edf47be34b8fccf76d21bf173b948db9d2199802d"
              },
              {
               "path": "/var/lib/dpkg/status",
               "layerID": "sha256:ddb7bdf7b2c1eeebb730b55edf47be34b8fccf76d21bf173b948db9d2199802d"
              }
             ],
             "language": "",
             "licenses": [
              "GPL-2"
             ],
             "cpes": [
              "cpe:2.3:a:passwd:passwd:1:4.8.1-1ubuntu5.20.04.1:*:*:*:*:*:*:*"
             ],
             "purl": "pkg:deb/ubuntu/passwd@1:4.8.1-1ubuntu5.20.04.1?arch=arm64&upstream=shadow&distro=ubuntu-20.04",
             "upstreams": [
              {
               "name": "shadow"
              }
             ]
            }
           },
           {
            "vulnerability": {
             "id": "CVE-2022-24407",
             "dataSource": "https://security-tracker.debian.org/tracker/CVE-2022-24407",
             "namespace": "debian:10",
             "severity": "High",
             "urls": [
              "https://security-tracker.debian.org/tracker/CVE-2022-24407"
             ],
             "description": "In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL INSERT or UPDATE statement.",
             "cvss": [],
             "fix": {
              "versions": [
               "2.1.27+dfsg-1+deb10u2"
              ],
              "state": "fixed"
             },
             "advisories": [
              {
               "id": "DSA-5087-1",
               "link": "https://security-tracker.debian.org/tracker/DSA-5087-1"
              }
             ]
            },
            "relatedVulnerabilities": [
             {
              "id": "CVE-2022-24407",
              "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2022-24407",
              "namespace": "nvd",
              "severity": "High",
              "urls": [
               "http://www.openwall.com/lists/oss-security/2022/02/23/4",
               "https://github.com/cyrusimap/cyrus-sasl/blob/fdcd13ceaef8de684dc69008011fa865c5b4a3ac/docsrc/sasl/release-notes/2.1/index.rst",
               "https://www.cyrusimap.org/sasl/sasl/release-notes/2.1/index.html#new-in-2-1-28",
               "https://www.debian.org/security/2022/dsa-5087",
               "https://lists.debian.org/debian-lts-announce/2022/03/msg00002.html",
               "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZZC6BMPI3V3MC2IGNLN377ETUWO7QBIH/",
               "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/H26R4SMGM3WHXX4XYNNJB4YGFIL5UNF4/",
               "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4FIXU75Q6RBNK6UYM7MQ3TCFGXR7AX4U/"
              ],
              "description": "In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL INSERT or UPDATE statement.",
              "cvss": [
               {
                "version": "2.0",
                "vector": "AV:N/AC:L/Au:S/C:P/I:P/A:P",
                "metrics": {
                 "baseScore": 6.5,
                 "exploitabilityScore": 8,
                 "impactScore": 6.4
                },
                "vendorMetadata": {}
               },
               {
                "version": "3.1",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "metrics": {
                 "baseScore": 8.8,
                 "exploitabilityScore": 2.8,
                 "impactScore": 5.9
                },
                "vendorMetadata": {}
               }
              ]
             }
            ],
            "matchDetails": [
             {
              "type": "exact-indirect-match",
              "matcher": "dpkg-matcher",
              "searchedBy": {
               "distro": {
                "type": "debian",
                "version": "10"
               },
               "namespace": "debian:10",
               "package": {
                "name": "cyrus-sasl2",
                "version": "2.1.27+dfsg-1+deb10u1"
               }
              },
              "found": {
               "versionConstraint": "< 2.1.27+dfsg-1+deb10u2 (deb)"
              }
             }
            ],
            "artifact": {
             "name": "libsasl2-modules-db",
             "version": "2.1.27+dfsg-1+deb10u1",
             "type": "deb",
             "locations": [
              {
               "path": "/usr/share/doc/libsasl2-modules-db/copyright",
               "layerID": "sha256:faac394a1ad320e6123d491e976781da28195672dbbe10783f79ecaf2d302f38"
              },
              {
               "path": "/var/lib/dpkg/info/libsasl2-modules-db:amd64.md5sums",
               "layerID": "sha256:faac394a1ad320e6123d491e976781da28195672dbbe10783f79ecaf2d302f38"
              },
              {
               "path": "/var/lib/dpkg/status",
               "layerID": "sha256:c77e5c692e7986a232bdb9a933e86606f69fcb6029edd8ddd513df411a705d2f"
              }
             ],
             "language": "",
             "licenses": [
              "BSD-4-clause",
              "GPL-3",
              "GPL-3+"
             ],
             "cpes": [
              "cpe:2.3:a:libsasl2-modules-db:libsasl2-modules-db:2.1.27+dfsg-1+deb10u1:*:*:*:*:*:*:*",
              "cpe:2.3:a:libsasl2-modules-db:libsasl2_modules_db:2.1.27+dfsg-1+deb10u1:*:*:*:*:*:*:*",
              "cpe:2.3:a:libsasl2_modules_db:libsasl2-modules-db:2.1.27+dfsg-1+deb10u1:*:*:*:*:*:*:*",
              "cpe:2.3:a:libsasl2_modules_db:libsasl2_modules_db:2.1.27+dfsg-1+deb10u1:*:*:*:*:*:*:*",
              "cpe:2.3:a:libsasl2-modules:libsasl2-modules-db:2.1.27+dfsg-1+deb10u1:*:*:*:*:*:*:*",
              "cpe:2.3:a:libsasl2-modules:libsasl2_modules_db:2.1.27+dfsg-1+deb10u1:*:*:*:*:*:*:*",
              "cpe:2.3:a:libsasl2_modules:libsasl2-modules-db:2.1.27+dfsg-1+deb10u1:*:*:*:*:*:*:*",
              "cpe:2.3:a:libsasl2_modules:libsasl2_modules_db:2.1.27+dfsg-1+deb10u1:*:*:*:*:*:*:*",
              "cpe:2.3:a:libsasl2:libsasl2-modules-db:2.1.27+dfsg-1+deb10u1:*:*:*:*:*:*:*",
              "cpe:2.3:a:libsasl2:libsasl2_modules_db:2.1.27+dfsg-1+deb10u1:*:*:*:*:*:*:*"
             ],
             "purl": "pkg:deb/debian/libsasl2-modules-db@2.1.27+dfsg-1+deb10u1?arch=amd64&upstream=cyrus-sasl2&distro=debian-10",
             "upstreams": [
              {
               "name": "cyrus-sasl2"
              }
             ]
            }
           }
    ],
    "source": {
     "type": "image",
     "target": {
      "userInput": "kalilinux/kali-rolling",
      "imageID": "sha256:e4dbb77afc663a8602b01a1afed57e303031dcf15c86f0664e20f25e0be398cf",
      "manifestDigest": "sha256:2e10e7ac3baea4d3e46bfda94865ba977ab2df7211667a7669c43c989f6cc269",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "tags": [
       "kalilinux/kali-rolling:latest"
      ],
      "imageSize": 120219444,
      "layers": [
       {
        "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "digest": "sha256:b0fc924e7fc3dd216409d817529e2856690e2e61d2c5faebf82e774bbfd50791",
        "size": 120219444
       }
      ],
      "manifest": "eyJzY2hlbWFWZXJzaW9uIjoyLCJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQuZG9ja2VyLmRpc3RyaWJ1dGlvbi5tYW5pZmVzdC52Mitqc29uIiwiY29uZmlnIjp7Im1lZGlhVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuY29udGFpbmVyLmltYWdlLnYxK2pzb24iLCJzaXplIjoyNzM2LCJkaWdlc3QiOiJzaGEyNTY6ZTRkYmI3N2FmYzY2M2E4NjAyYjAxYTFhZmVkNTdlMzAzMDMxZGNmMTVjODZmMDY2NGUyMGYyNWUwYmUzOThjZiJ9LCJsYXllcnMiOlt7Im1lZGlhVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5kb2NrZXIuaW1hZ2Uucm9vdGZzLmRpZmYudGFyLmd6aXAiLCJzaXplIjoxMjU1NzMxMjAsImRpZ2VzdCI6InNoYTI1NjpiMGZjOTI0ZTdmYzNkZDIxNjQwOWQ4MTc1MjllMjg1NjY5MGUyZTYxZDJjNWZhZWJmODJlNzc0YmJmZDUwNzkxIn1dfQ==",
      "config": "eyJhcmNoaXRlY3R1cmUiOiJhcm02NCIsImNvbmZpZyI6eyJFbnYiOlsiUEFUSD0vdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4iXSwiQ21kIjpbImJhc2giXSwiV29ya2luZ0RpciI6Ii8iLCJMYWJlbHMiOnsib3JnLm9wZW5jb250YWluZXJzLmltYWdlLmF1dGhvcnMiOiJLYWxpIERldmVsb3BlcnMgXHUwMDNjZGV2ZWxAa2FsaS5vcmdcdTAwM2UiLCJvcmcub3BlbmNvbnRhaW5lcnMuaW1hZ2UuY3JlYXRlZCI6IjIwMjItMDQtMThUMDU6NDg6MjlaIiwib3JnLm9wZW5jb250YWluZXJzLmltYWdlLmRlc2NyaXB0aW9uIjoiT2ZmaWNpYWwgS2FsaSBMaW51eCBjb250YWluZXIgaW1hZ2UgZm9yIGthbGktcm9sbGluZyIsIm9yZy5vcGVuY29udGFpbmVycy5pbWFnZS5yZXZpc2lvbiI6IjgwNjBkMWEiLCJvcmcub3BlbmNvbnRhaW5lcnMuaW1hZ2Uuc291cmNlIjoiaHR0cHM6Ly9naXRsYWIuY29tL2thbGlsaW51eC9idWlsZC1zY3JpcHRzL2thbGktZG9ja2VyIiwib3JnLm9wZW5jb250YWluZXJzLmltYWdlLnRpdGxlIjoiS2FsaSBMaW51eCAoa2FsaS1yb2xsaW5nIGJyYW5jaCkiLCJvcmcub3BlbmNvbnRhaW5lcnMuaW1hZ2UudXJsIjoiaHR0cHM6Ly93d3cua2FsaS5vcmcvIiwib3JnLm9wZW5jb250YWluZXJzLmltYWdlLnZlbmRvciI6Ik9mZmVuc2l2ZSBTZWN1cml0eSIsIm9yZy5vcGVuY29udGFpbmVycy5pbWFnZS52ZXJzaW9uIjoiMjAyMi4wNC4xOCJ9LCJBcmdzRXNjYXBlZCI6dHJ1ZSwiT25CdWlsZCI6bnVsbH0sImNyZWF0ZWQiOiIyMDIyLTA0LTE4VDEyOjQ4OjMyLjgwOTQyNDU5NiswNzowMCIsImhpc3RvcnkiOlt7ImNyZWF0ZWQiOiIyMDIyLTA0LTE4VDEyOjQ4OjMyLjgwOTQyNDU5NiswNzowMCIsImNyZWF0ZWRfYnkiOiJBUkcgQlVJTERfREFURSIsImNvbW1lbnQiOiJidWlsZGtpdC5kb2NrZXJmaWxlLnYwIiwiZW1wdHlfbGF5ZXIiOnRydWV9LHsiY3JlYXRlZCI6IjIwMjItMDQtMThUMTI6NDg6MzIuODA5NDI0NTk2KzA3OjAwIiwiY3JlYXRlZF9ieSI6IkFSRyBWRVJTSU9OIiwiY29tbWVudCI6ImJ1aWxka2l0LmRvY2tlcmZpbGUudjAiLCJlbXB0eV9sYXllciI6dHJ1ZX0seyJjcmVhdGVkIjoiMjAyMi0wNC0xOFQxMjo0ODozMi44MDk0MjQ1OTYrMDc6MDAiLCJjcmVhdGVkX2J5IjoiQVJHIFBST0pFQ1RfVVJMIiwiY29tbWVudCI6ImJ1aWxka2l0LmRvY2tlcmZpbGUudjAiLCJlbXB0eV9sYXllciI6dHJ1ZX0seyJjcmVhdGVkIjoiMjAyMi0wNC0xOFQxMjo0ODozMi44MDk0MjQ1OTYrMDc6MDAiLCJjcmVhdGVkX2J5IjoiQVJHIFZDU19SRUYiLCJjb21tZW50IjoiYnVpbGRraXQuZG9ja2VyZmlsZS52MCIsImVtcHR5X2xheWVyIjp0cnVlfSx7ImNyZWF0ZWQiOiIyMDIyLTA0LTE4VDEyOjQ4OjMyLjgwOTQyNDU5NiswNzowMCIsImNyZWF0ZWRfYnkiOiJBUkcgVEFSQkFMTCIsImNvbW1lbnQiOiJidWlsZGtpdC5kb2NrZXJmaWxlLnYwIiwiZW1wdHlfbGF5ZXIiOnRydWV9LHsiY3JlYXRlZCI6IjIwMjItMDQtMThUMTI6NDg6MzIuODA5NDI0NTk2KzA3OjAwIiwiY3JlYXRlZF9ieSI6IkFSRyBSRUxFQVNFX0RFU0NSSVBUSU9OIiwiY29tbWVudCI6ImJ1aWxka2l0LmRvY2tlcmZpbGUudjAiLCJlbXB0eV9sYXllciI6dHJ1ZX0seyJjcmVhdGVkIjoiMjAyMi0wNC0xOFQxMjo0ODozMi44MDk0MjQ1OTYrMDc6MDAiLCJjcmVhdGVkX2J5IjoiTEFCRUwgb3JnLm9wZW5jb250YWluZXJzLmltYWdlLmNyZWF0ZWQ9MjAyMi0wNC0xOFQwNTo0ODoyOVogb3JnLm9wZW5jb250YWluZXJzLmltYWdlLnNvdXJjZT1odHRwczovL2dpdGxhYi5jb20va2FsaWxpbnV4L2J1aWxkLXNjcmlwdHMva2FsaS1kb2NrZXIgb3JnLm9wZW5jb250YWluZXJzLmltYWdlLnJldmlzaW9uPTgwNjBkMWEgb3JnLm9wZW5jb250YWluZXJzLmltYWdlLnZlbmRvcj1PZmZlbnNpdmUgU2VjdXJpdHkgb3JnLm9wZW5jb250YWluZXJzLmltYWdlLnZlcnNpb249MjAyMi4wNC4xOCBvcmcub3BlbmNvbnRhaW5lcnMuaW1hZ2UudGl0bGU9S2FsaSBMaW51eCAoa2FsaS1yb2xsaW5nIGJyYW5jaCkgb3JnLm9wZW5jb250YWluZXJzLmltYWdlLmRlc2NyaXB0aW9uPU9mZmljaWFsIEthbGkgTGludXggY29udGFpbmVyIGltYWdlIGZvciBrYWxpLXJvbGxpbmcgb3JnLm9wZW5jb250YWluZXJzLmltYWdlLnVybD1odHRwczovL3d3dy5rYWxpLm9yZy8gb3JnLm9wZW5jb250YWluZXJzLmltYWdlLmF1dGhvcnM9S2FsaSBEZXZlbG9wZXJzIFx1MDAzY2RldmVsQGthbGkub3JnXHUwMDNlIiwiY29tbWVudCI6ImJ1aWxka2l0LmRvY2tlcmZpbGUudjAiLCJlbXB0eV9sYXllciI6dHJ1ZX0seyJjcmVhdGVkIjoiMjAyMi0wNC0xOFQxMjo0ODozMi44MDk0MjQ1OTYrMDc6MDAiLCJjcmVhdGVkX2J5IjoiQUREIGthbGktcm9sbGluZy1hcm02NC50YXIueHogLyAjIGJ1aWxka2l0IiwiY29tbWVudCI6ImJ1aWxka2l0LmRvY2tlcmZpbGUudjAifSx7ImNyZWF0ZWQiOiIyMDIyLTA0LTE4VDEyOjQ4OjMyLjgwOTQyNDU5NiswNzowMCIsImNyZWF0ZWRfYnkiOiJDTUQgW1wiYmFzaFwiXSIsImNvbW1lbnQiOiJidWlsZGtpdC5kb2NrZXJmaWxlLnYwIiwiZW1wdHlfbGF5ZXIiOnRydWV9XSwib3MiOiJsaW51eCIsInJvb3RmcyI6eyJ0eXBlIjoibGF5ZXJzIiwiZGlmZl9pZHMiOlsic2hhMjU2OmIwZmM5MjRlN2ZjM2RkMjE2NDA5ZDgxNzUyOWUyODU2NjkwZTJlNjFkMmM1ZmFlYmY4MmU3NzRiYmZkNTA3OTEiXX19",
      "repoDigests": [
       "kalilinux/kali-rolling@sha256:f6f0a342271a97746f8fec9dff4cb49b198b5f3f47cf5b074e1a0daf3ee5a8da"
      ],
      "architecture": "arm64",
      "os": "linux"
     }
    },
    "distro": {
     "name": "debian",
     "version": "2022.1",
     "idLike": [
      "debian"
     ]
    },
    "descriptor": {
     "name": "grype",
     "version": "0.35.0",
     "configuration": {
      "configPath": "",
      "output": "json",
      "file": "",
      "distro": "",
      "add-cpes-if-none": false,
      "output-template-file": "",
      "quiet": false,
      "check-for-app-update": true,
      "only-fixed": false,
      "platform": "",
      "search": {
       "scope": "Squashed",
       "unindexed-archives": false,
       "indexed-archives": true
      },
      "ignore": null,
      "exclude": [],
      "db": {
       "cache-dir": "/Users/lap02173/Library/Caches/grype/db",
       "update-url": "https://toolbox-data.anchore.io/grype/databases/listing.json",
       "ca-cert": "",
       "auto-update": true,
       "validate-by-hash-on-start": false
      },
      "externalSources": {
       "enable": false,
       "maven": {
        "searchUpstreamBySha1": true,
        "baseUrl": "https://search.maven.org/solrsearch/select"
       }
      },
      "dev": {
       "profile-cpu": false,
       "profile-mem": false
      },
      "fail-on-severity": "",
      "registry": {
       "insecure-skip-tls-verify": false,
       "insecure-use-http": false,
       "auth": []
      },
      "log": {
       "structured": false,
       "level": "",
       "file": ""
      }
     },
     "db": {
      "built": "2022-04-21T08:14:29Z",
      "schemaVersion": 3,
      "location": "/Users/lap02173/Library/Caches/grype/db/3",
      "checksum": "sha256:07c5186921abeea4ed27f2b19fa88692541f0f4d74f120ce8ba3896f5f96a1f3",
      "error": null
     }
    }
   }
   `;

const hehe = JSON.parse(result)

const findings = [];

for (let i = 0; i < hehe.matches.length; i++) {
    findings.push({
        name: "Grype scan image " + hehe.source.target.tags[0],
        description: hehe.matches[i].vulnerability.id,
        category: "Grype scan image",
        location: hehe.source.target.userInput,
        osi_layer: "APPLICATION",
        severity: hehe.matches[i].vulnerability.severity.toUpperCase(),
        reference: {},
        confidence: hehe.matches[i].vulnerability.urls,
        attributes: {}
    })
  }



console.log(findings)