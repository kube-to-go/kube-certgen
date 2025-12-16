package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

type Certificate struct {
	template      x509.Certificate
	certDER       []byte
	certPEM       string
	fpSha1        string
	fpSha256      string
	privateKey    *ecdsa.PrivateKey
	privateKeyPEM string
}

func generateRootCACert(commonName string) (Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return Certificate{}, err
	}

	// TODO: configurable duration
	template, err := createTemplate(commonName, false, 90)
	if err != nil {
		return Certificate{}, err
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return Certificate{}, err
	}

	certPEM := encodeCertificate(certDER)
	privateKeyPEM, err := encodeKey(privateKey)

	fpSha1, fpSha256 := certFingerprint(certDER)

	return Certificate{template, certDER, certPEM, fpSha1, fpSha256, privateKey, privateKeyPEM}, nil
}

func generateLeafCert(commonName string, hosts []string, parent Certificate) (Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return Certificate{}, err
	}

	// TODO: configurable duration
	template, err := createTemplate(commonName, false, 90)
	if err != nil {
		return Certificate{}, err
	}

	// Add SANs
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// Create a certificate signed with the parent certificate's key
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &parent.template, &privateKey.PublicKey, parent.privateKey)
	if err != nil {
		return Certificate{}, err
	}

	certPEM := encodeCertificate(certDER)
	privateKeyPEM, err := encodeKey(privateKey)

	fpSha1, fpSha256 := certFingerprint(certDER)

	return Certificate{template, certDER, certPEM, fpSha1, fpSha256, privateKey, privateKeyPEM}, nil
}

func createTemplate(commonName string, isCA bool, validity_days uint) (x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return x509.Certificate{}, err
	}

	var keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if isCA {
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	return x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(validity_days) * 24 * time.Hour),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}, nil
}

func encodeCertificate(certDER []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func encodeKey(private_key *ecdsa.PrivateKey) (string, error) {
	keyBytes, err := x509.MarshalECPrivateKey(private_key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})), nil
}

func certFingerprint(certDER []byte) (string, string) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}

	sha256sum := sha256.Sum256(cert.Raw)
	sha1sum := sha1.Sum(cert.Raw)

	return formatFingerprint(sha1sum[:]), formatFingerprint(sha256sum[:])
}

func formatFingerprint(hash []byte) string {
	var buffer bytes.Buffer

	for i, b := range hash {
		if i > 0 {
			buffer.WriteByte(':')
		}
		fmt.Fprintf(&buffer, "%02X", b)
	}

	return buffer.String()
}
