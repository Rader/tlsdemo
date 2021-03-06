package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
)

const caPEM = `-----BEGIN CERTIFICATE-----
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

const srvPEM = `-----BEGIN CERTIFICATE-----
MIIC9TCCAd2gAwIBAgIBATANBgkqhkiG9w0BAQQFADByMQ4wDAYDVQQDEwVrYW1j
YTEPMA0GA1UECBMGTmV2YWRhMQswCQYDVQQGEwJVUzEcMBoGCSqGSIb3DQEJARYN
a2FtQGthbWNhLm9yZzEkMCIGA1UEChMbS0FNIENlcnRpZmljYXRpb24gQXV0aG9y
aXR5MB4XDTA0MDgyNjE4MjMyM1oXDTI0MDgyMTE4MjMyM1owfzENMAsGA1UEAxME
TWlrZTEPMA0GA1UECBMGTmV2YWRhMQswCQYDVQQGEwJVUzEjMCEGCSqGSIb3DQEJ
ARYUbWlrZS5raW5zbGV5QGlndC5jb20xDDAKBgNVBAoTA0lHVDEdMBsGA1UECxMU
SGFyZHdhcmUgRW5naW5lZXJpbmcwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB
ALKZ/CNoNZSBkomZsS/pVXO9LdAHp8VAPGGFQ8dfaj+GCuSoYKydgPmShI+eUS6/
eU59JVUlXw98Trfhyo7MG9+MeQtFE12+GtaMQYlzTkeKtOpCyYtJfzm1A9cxQ5wJ
+Qf/FBtNx1gGz/ppgZQbeFrvvPxfaD6/RXXHGS++0Dg7AgMBAAGjDTALMAkGA1Ud
EwQCMAAwDQYJKoZIhvcNAQEEBQADggEBAJumt9tvK/Gbk8ts5E1cGbpI604zzCr8
erA9TMp4QjvjLvwqRD6uUqNx5LkKieB7Zlzwf+V6X5evoK7/UPu8DUqogc64F9qm
FhjmUjjvdA5Vssm4dS711twpiZ7X3JjSNuLXxSQjJBn1yeZRpiV3JjC0Kcqey4IO
PIoQWLJm/gO/zQFZ5Z3ESLv9zW6feiCNcSTC6YnZsxA74WsqenljLLwnkOUng3x4
Rwk33cZ4uxiX/zvVLTxI4u3hrLUmL4Kkgnn8F4gkf2bGqjEMjbOp1uzXg0VIqIAN
QW2r2Mc3y6fRQka9QAB8eaGmxb7pYzkVmf/oz7Fz2P6txAW0mjJDaSo=
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,706F2681548A01B6

0o4127gh5+2OfZKwfdQTw9cwTr1xtsIJ8wBgocRevsNCcg+rWm6FC0pHI0bUtLil
4cd1BjysSQBQlZyp4NGI/2c/1MZE4+si+CHvEfYVgBjVNDFxQGBt9PBnphyzVn0s
XyT8hMd6/9c/KO3JHD85b7N7qrlB8Ja6IpWWPWTEJjITISyyhofuAkTlgPc94g+f
JrNCBbtjWcQ5BsTItkB4FCBMsMBfTlhW5P/JrGop2R4aRK+B/SeOoZ5VA10VA6ef
pfmh2NTcJ3hxO7u2QIdsUnHjCOrNTq8PnIfc1fndQe+nTsihwJTPpwtp1pQzFJIl
YvncQmx1LRKXmB6I/5nI+5sYG2/tw6Hxm73grUnjFukXfgUL7QJbMVf4r2Hbz1N/
c13B8Dh0qAO3/fmGLPDjmLroJIX7pv6MbidIP7Ti6DaOOpygYm3BlqfeLMcPRqZG
llq7q1MgYiiRrlWpVPTKAiQUpuBzLkJu6p+ANapV1120sbJcLxApbNhipPE0bNOf
d9zDffrzKxf2m+sT2wByxK0C2OgZHku2GukdObxpIKuser87TgCDBQBsID4tiMVF
7il0z+SHA4fXUEDYYfWoXQyzSOCUd8LDVQvNI8Vmxyri0m+cFOkOganAn2OQFi3V
cft0UX42aLvi9cszLRm2XuUMCm+M512wpqDL4kxdle6TFDtJQKsDgYBZY5mvp34b
XPnSYCFC7TYDgzOcwwfktmxnA8DBuucJIc8GEKxuK89ftQMJS9QniAIAb4F32tKc
QSgZZMtwn93NESz5uM82z/Jzyhs5411ixPf7bEKU3n+MKyFnQmaWwA==
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

func main() {
	ls, err := net.Listen("tcp", ":56000")
	if err != nil {
		fmt.Println("Failed to listen")
		return
	}

	fmt.Println("I am server")
	for {
		conn, err := ls.Accept()
		if err != nil {
			fmt.Println("Failed to accept")
			continue
		}

		s := "Hello client"

		conn.Write([]byte(s))

		rootCAs := x509.NewCertPool()
		rootCAs.AppendCertsFromPEM([]byte(caPEM))
		tlsConfig := &tls.Config{RootCAs: rootCAs}
		tlsConfig.ClientAuth = tls.NoClientCert
		tlsConn := tls.Server(conn, tlsConfig)
		err = tlsConn.Handshake()
		if err != nil {
			log.Println(err.Error())
		}
		log.Println("TLS Handshake done.")

		tlsConn.Write([]byte("Hell client from SSL connection."))
	}

}
