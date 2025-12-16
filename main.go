package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	namespace, secretName, commonName := getParameters()

	log.Printf("Generating certificate (CN: \"%s\")...\n", commonName)
	certPEM, keyPEM, err := generateSelfSignedCert(commonName)
	if err != nil {
		log.Fatalf("Error generating certificate: %v", err)
	}
	log.Printf("Certificate (CN: \"%s\") generated successfully.\n", commonName)

	fmt.Printf(string(certPEM))

	if namespace != "" && secretName != "" {
		log.Printf("Applying secret \"%s\" (namespace \"%s\")...\n", secretName, namespace)
		deploySecret(namespace, secretName, certPEM, keyPEM)
		log.Printf("Secret \"%s\" (namespace \"%s\") successfully applied\n", secretName, namespace)
	}
}

func getParameters() (string, string, string) {
	namespace := os.Getenv("NAMESPACE")
	secretName := os.Getenv("SECRET")
	commonName := os.Getenv("CERT_CN")

	if commonName == "" {
		// if secretName == "" || namespace == "" || commonName == "" {
		log.Fatalf("SECRET, NAMESPACE, and CERT_CN environment variables must be set")
	}

	return namespace, secretName, commonName
}

func generateSelfSignedCert(commonName string) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}

	// TODO: configurable duration
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour), // 90 days
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	fpSha1, fpSha256 := certFingerprint(derBytes)
	log.Printf("FP (sha1):    %s", fpSha1)
	log.Printf("FP (sha256):  %s", fpSha256)

	// PEM-encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// PEM-encode private key
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
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

func deploySecret(namespace string, secretName string, certPEM []byte, keyPEM []byte) {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Error creating kubernetes in-cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating kubernetes clientset: %v", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}

	_, err = clientset.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	if err != nil {
		_, err = clientset.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
		if err != nil {
			log.Fatalf("Failed to create or update secret: %v", err)
		}
	}
}
