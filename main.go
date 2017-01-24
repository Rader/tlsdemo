package main

import "encoding/pem"
import "crypto/x509"

import "fmt"
import "strings"
import "encoding/hex"
import "crypto/des"
import "crypto/cipher"
import "log"

func main() {
	data := []byte(clientPEM)
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			if isEncrypted(block) {
				dekInfo := block.Headers["DEK-Info"]
				ss := strings.Split(dekInfo, ",")
				ivStr := ss[1]
				iv, err := hex.DecodeString(ivStr)
				if err != nil {
					log.Fatalln(err.Error())
				}
				pass := []byte("igtasd")
				key := make([]byte, 24)
				copy(key, pass)
				desBlock, err := des.NewTripleDESCipher(key)
				if err != nil {
					log.Fatalln(err.Error())
				}
				mode := cipher.NewCBCDecrypter(desBlock, iv)
                
				mode.CryptBlocks(block.Bytes, block.Bytes)
			}
			privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			fmt.Printf("%+v", privateKey)
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			fmt.Printf("%+v", cert)
		}
	}
}

func isEncrypted(b *pem.Block) bool {
	procType := b.Headers["Proc-Type"]
	return strings.Contains(procType, "ENCRYPTED")
}

const clientPEM = `-----BEGIN CERTIFICATE-----
MIIC9TCCAd2gAwIBAgIBATANBgkqhkiG9w0BAQQFADByMQ4wDAYDVQQDEwVrYW1j
YTEPMA0GA1UECBMGTmV2YWRhMQswCQYDVQQGEwJVUzEcMBoGCSqGSIb3DQEJARYN
a2FtQGthbWNhLm9yZzEkMCIGA1UEChMbS0FNIENlcnRpZmljYXRpb24gQXV0aG9y
aXR5MB4XDTA0MDgyNjE4MTk1N1oXDTI0MDgyMTE4MTk1N1owfzENMAsGA1UEAxME
TWlrZTEPMA0GA1UECBMGTmV2YWRhMQswCQYDVQQGEwJVUzEjMCEGCSqGSIb3DQEJ
ARYUbWlrZS5raW5zbGV5QGlndC5jb20xDDAKBgNVBAoTA0lHVDEdMBsGA1UECxMU
SGFyZHdhcmUgRW5naW5lZXJpbmcwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB
AMUdCQ+ObkIiW6/9RbL+zPCenMlIMVac9gQhAhNhBW/C2JEC6KFvB7rFkbHELXn2
cYv0ud2OiwTp/8XVEEFEH6Lmv81p8lUNr8h4xVGNW+NmtitHeYib7TVwpce32Cnb
Wje5p/88zrYP6UO7VJ5u7eOS6ZloJ86+yDlbplOt7XYtAgMBAAGjDTALMAkGA1Ud
EwQCMAAwDQYJKoZIhvcNAQEEBQADggEBANxnV4UNpvmFVD7sK1c+sADZ8gFaHegY
xkHwWPLhJQFNBk92Jzcel9VLnmV2drbAUR9YCSbilGl+JbgW+mitFi0p2ZuX1Hdw
Z+iGlOCI77s/SBbs3XLer+24VytMGmKRq8/zCTAAmjPOzMTnykESp/8QKrqJwKXb
ZbyJmFcxwA+aer+mitwANTi4Y/YD/bSc/WC1//8oZwOJfS4915mPLhqa68gD68um
6fhMhZECopb3GO1DPRASFuXISsSUuWURQj0de4dleOzljirT+41LFOi1E51jLWJ+
BUIYmrqOUdOYoZRbVL9ahOPeKt0eOptoc4esIZeMERi761Sc98apkH4=
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,FA0DD6FA1330D84A

xBisqkREN2Dfnu1ohYmrr0KpokrJqGwR2jKvHp4SyvxDWs5DMVIOVuCfFxtN4PsV
pCts/gZGxmn2p7rijN/dCr5HgSGjmNv4lA/DRhwFRRWxftB7MNC/mZokkh8urDKD
FIv10vYxsi6jNUw6n59s1NaBoJFhDWIkAXh53XN02R8r/8RPIJgOSNhMm9ldUPvp
X8SkGYJKXDt7dxmdsP1OGhk0uYkLgwmJV5sCtNKBp+yQrzFqv2+HVIHbXacSS1hV
pvOLsOfCpRpAvQeNOEyc3Y614c3t5Pn6t3ehR4ahfvYnQ+fGQ4aWbi+h5f1fruYY
jNrqri9T5BlJxyZ819FsgJBAwZnM1Fhbvzi1rXdU+G6MCac9bzWWkjKfrY07/Fdo
CTV7RCyFWWwCH/tixtxULUQ4gQbFKhujBvxgBww4zx58QZRFpTm3fy68e/hJY4yP
UV6Dx14LTNMT+9TnXunThMy64J4Roz4Sv/3U+pQb97oDCSD7nLQF84l6bNzDA2hQ
KBUh4vhs9GHdaRNL79inv2NhjNHyr8EThYJ/2ypk9i8Fn1e4lPHzb5mTScfa/ozH
4Gz+3z0R84E286UYSifp0aH9iiI5cTR4iqPEYdZVb60eRPPAlggDPKqDZY2cz4x0
MbjVk4gB3tCxulXIEIVdioF8nR5wOVNDbrRBnaZaQkp2a46FCzz65gGlB/2rvby2
qTsvYU5DysqJjpNOOlbmFw90qGZq1aPQcFvC9qffeTIg+CMvoitH+pNJ4WGTI/XZ
lINppFFTzBCdbOPhv7mboF5HTaQohSGXKGhsF7TvOic4jj+r4eT0Ag==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDbzCCAlegAwIBAgIBADANBgkqhkiG9w0BAQQFADByMQ4wDAYDVQQDEwVrYW1j
YTEPMA0GA1UECBMGTmV2YWRhMQswCQYDVQQGEwJVUzEcMBoGCSqGSIb3DQEJARYN
a2FtQGthbWNhLm9yZzEkMCIGA1UEChMbS0FNIENlcnRpZmljYXRpb24gQXV0aG9y
aXR5MB4XDTA0MDgyNjE4MTgxN1oXDTI0MDgyMTE4MTgxN1owcjEOMAwGA1UEAxMF
a2FtY2ExDzANBgNVBAgTBk5ldmFkYTELMAkGA1UEBhMCVVMxHDAaBgkqhkiG9w0B
CQEWDWthbUBrYW1jYS5vcmcxJDAiBgNVBAoTG0tBTSBDZXJ0aWZpY2F0aW9uIEF1
dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN/KzWVEs1ko
ejEqLczKEG2UTjFxwGvQzgyTV8OGqNeWyE6UgpfZFzZZ/YOVWC1hdJVxkFdLe0bQ
7TPvY8SCwBTUuCXfz23ASd3u86WhqHo4tAJvf/TslkBD/jgLz49pWwZVRcBuC0tw
zHsdiRJ7jPY0se4aYLmhOI5v+KqGos65F2ujnAoQGLTl102J0A8fEQOQNs2WNdPT
f4Pq49FRG39c2ziFr+EzO5fA3u0JRp/0y6Zr0V+CtRRjaSOabARIPue2YuMryAUu
47amXqNomOHiV72Eksw2NZItwCA7IyppJzH3kiCrb4Mo85uRcRULg1vj9NeZGdX9
Bk1mxE65FMcCAwEAAaMQMA4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQQFAAOC
AQEAMHbFDuMOjiq3auv6eMTFa7TYCk/kmSC3cYsoFd2VTyinjQ1qT7JaBelPgV2i
MTU/Kq6FbYByqjPky3Up4lVwM1UqyFbC8ydQr99zmBQypp6DCSlJULIlAbAFtWSc
RQx6x8ILfGQmPdSs+ON6VPlg/Oqf0nGUhnwq+DmhKrJIeUM5utJ7L+FRgf5NMxnX
qbWiF0jrDvUgBkIGrm96UmPm68YDkNqH5E9mBnxCe0MemTecO0+KCL3sVmgAQdMw
QXoJoU5WxYdE9rexWtoCijTEwiD5rxM1IoLJMKcvsOHvUJNG3RQ6HeqfssSKER/s
F38xAhlVAw/WEcJqGt/GI4hsnw==
-----END CERTIFICATE-----`
