package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

const (
	caCert = "key1/test.crt"
	caPri  = "key1/test.key"
)

func newKey(host string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(caCert, caPri)
	if err != nil {
		log.Fatal(err)
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			Country:            []string{"US"},
			StreetAddress:      []string{"Oklahoma"},
			Locality:           []string{"Stillwater"},
			Organization:       []string{"My Company"},
			OrganizationalUnit: []string{"Engineering"},
			CommonName:         host,
			SerialNumber:       "1234",
		},
		DNSNames:              []string{host},
		SerialNumber:          new(big.Int).SetInt64(int64(time.Now().UnixNano())),
		IsCA:                  false,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, //证书用途(客户端认证，数据加密)
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
	}
	newCert, err := x509.CreateCertificate(rand.Reader, &template, x509Cert, x509Cert.PublicKey, cert.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	pri, err := ioutil.ReadFile(caPri)
	if err != nil {
		log.Fatal(err)
	}

	cert1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert})
	crt, err := tls.X509KeyPair(cert1, pri)

	return &crt, err
}
