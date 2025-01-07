package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

)

type Query struct {
	OrgDomain string `json:"orgDomain"`
}

func main() {
	var caPEM, serverCertPEM, serverPrivKeyPEM *bytes.Buffer
	var query Query
	if err := json.NewDecoder(os.Stdin).Decode(&query); err != nil {
		log.Fatalf("failed to decode JSON from stdin: %v", err)
	}
	orgDomain := query.OrgDomain
	// CA config
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization: []string{orgDomain},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// CA private key
	caPrivKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
	}

	// Self signed CA certificate
	caBytes, err := x509.CreateCertificate(cryptorand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// PEM encode CA cert
	caPEM = new(bytes.Buffer)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	dnsNames := []string{"pod-identity-webhook",
		"pod-identity-webhook.irsa", "pod-identity-webhook.irsa.svc"}
	commonName := "pod-identity-webhook.irsa.svc"

	// server cert config
	cert := &x509.Certificate{
		DNSNames:     dnsNames,
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{orgDomain},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// server private key
	serverPrivKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
	}

	// sign the server cert
	serverCertBytes, err := x509.CreateCertificate(cryptorand.Reader, cert, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// PEM encode the  server cert and key
	serverCertPEM = new(bytes.Buffer)
	_ = pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	})

	serverPrivKeyPEM = new(bytes.Buffer)
	_ = pem.Encode(serverPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	})


	serverCertPEMBase64 := base64.StdEncoding.EncodeToString(serverCertPEM.Bytes())
	serverPrivKeyPEMBase64 := base64.StdEncoding.EncodeToString(serverPrivKeyPEM.Bytes())
	caPEMBase64 := base64.StdEncoding.EncodeToString(caPEM.Bytes())

	result := &Result{
		ServerCertPEMBase64: serverCertPEMBase64,
		ServerPrivKeyPEMBases64: serverPrivKeyPEMBase64,
		CaPEMBase64: caPEMBase64,
	}

	result := &Result{
		ServerCertPEMBase64: serverCertPEM.String(),
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(resultJSON))

}

type Result struct {
	ServerCertPEMBase64 string `json:"serverCertPEMBase64"`
	ServerPrivKeyPEMBases64 string `json:"serverPrivKeyPEMBases64"`
	CaPEMBase64 string `json:"caPEMBase64"`
}

