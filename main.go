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
	"net"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	commonName, hosts, namespace, secretName, configMapName := getParameters()

	log.Printf("Generating certificate (CN: \"%s\")...\n", commonName)
	certPEM, keyPEM, err := generateCertificate(commonName, hosts)
	if err != nil {
		log.Fatalf("Error generating certificate: %v", err)
	}
	log.Printf("Certificate (CN: \"%s\") generated successfully.\n", commonName)

	fmt.Printf(string(certPEM))

	if namespace != "" {
		cs := clientset()

		if secretName != "" {
			log.Printf("Applying secret \"%s\" (namespace \"%s\")...\n", secretName, namespace)
			deploySecret(cs, namespace, secretName, certPEM, keyPEM)
			log.Printf("Secret \"%s\" (namespace \"%s\") successfully applied\n", secretName, namespace)
		}

		if configMapName != "" {
			log.Printf("Applying config map \"%s\" (namespace \"%s\")...\n", secretName, namespace)
			deployConfigMap(cs, namespace, configMapName, certPEM)
			log.Printf("Config map \"%s\" (namespace \"%s\") successfully applied\n", secretName, namespace)
		}
	}
}

func getParameters() (string, []string, string, string, string) {
	commonName := os.Getenv("CERT_CN")
	rawHosts := os.Getenv("CERT_HOSTS")
	namespace := os.Getenv("NAMESPACE")
	secretName := os.Getenv("SECRET")
	configMapName := os.Getenv("CONFIGMAP")

	if commonName == "" {
		// if secretName == "" || namespace == "" || commonName == "" {
		log.Fatalf("The CERT_CN environment variables must be set")
		// log.Fatalf("SECRET, NAMESPACE, and CERT_CN environment variables must be set")
	}

	hosts := splitOn(rawHosts, ",")

	log.Printf("CERT_CN:    %s\n", commonName)
	log.Printf("CERT_HOSTS: %s\n", hosts)
	log.Printf("NAMESPACE:  %s\n", namespace)
	log.Printf("SECRET:     %s\n", secretName)
	log.Printf("CONFIGMAP:  %s\n", configMapName)

	return commonName, hosts, namespace, secretName, configMapName
}

func splitOn(value string, delimiter string) []string {
	parts := strings.Split(value, delimiter)

	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	return parts
}

func generateCertificate(commonName string, hosts []string) ([]byte, []byte, error) {
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

	// Add SANs
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
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

func clientset() kubernetes.Clientset {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Error creating kubernetes in-cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating kubernetes clientset: %v", err)
	}

	return *clientset
}

func deploySecret(clientset kubernetes.Clientset, namespace string, secretName string, certPEM []byte, keyPEM []byte) {
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

	_, err := clientset.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	if err != nil {
		_, err = clientset.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
		if err != nil {
			log.Fatalf("Failed to create or update secret: %v", err)
		}
	}
}

func deployConfigMap(clientset kubernetes.Clientset, namespace string, configMapName string, certPEM []byte) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			"tls.crt": string(certPEM),
		},
	}

	_, err := clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), cm, metav1.CreateOptions{})
	if err != nil {
		_, err = clientset.CoreV1().ConfigMaps(namespace).Update(context.TODO(), cm, metav1.UpdateOptions{})
		if err != nil {
			log.Fatalf("Failed to create or update config map: %v", err)
		}
	}
}
