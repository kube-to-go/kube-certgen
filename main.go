package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Parameters struct {
	rootCAConfigMapNamespace string
	rootCAConfigMapName      string
	rootCASecretNamespace    string
	rootCASecretName         string
	rootCACertCN             string

	leafConfigMapNamespace string
	leafConfigMapName      string
	leafSecretNamespace    string
	leafSecretName         string
	leafCertCN             string
	leafCertHosts          []string
}

func main() {
	log.Printf("Starting...")

	params := getParameters()

	rootCACert, err := generateRootCACert(params.rootCACertCN)
	if err != nil {
		log.Fatalf("Error generating root CA certificate: %v", err)
	}
	log.Printf("Generated root CA certificate")
	log.Printf("FP (sha1):    %s", rootCACert.fpSha1)
	log.Printf("FP (sha256):  %s", rootCACert.fpSha256)
	fmt.Printf(rootCACert.certPEM)

	leafCert, err := generateLeafCert(params.leafCertCN, params.leafCertHosts, rootCACert)
	if err != nil {
		log.Fatalf("Error generating leaf certificate: %v", err)
	}
	log.Printf("Generated leaf certificate")
	log.Printf("FP (sha1):    %s", leafCert.fpSha1)
	log.Printf("FP (sha256):  %s", leafCert.fpSha256)
	fmt.Printf(leafCert.certPEM)

	if params.rootCAConfigMapNamespace != "" ||
		params.rootCASecretNamespace != "" ||
		params.leafConfigMapNamespace != "" ||
		params.leafSecretNamespace != "" {

		cs := clientset()

		if params.rootCASecretNamespace != "" && params.rootCASecretName != "" {
			deploySecret(cs, params.rootCASecretNamespace, params.rootCASecretName, rootCACert.certPEM, rootCACert.privateKeyPEM)
		}

		if params.rootCAConfigMapNamespace != "" && params.rootCAConfigMapName != "" {
			deployConfigMap(cs, params.rootCAConfigMapNamespace, params.rootCAConfigMapName, rootCACert.certPEM)
		}

		if params.leafSecretNamespace != "" && params.leafSecretName != "" {
			deploySecret(cs, params.leafSecretNamespace, params.leafSecretName, leafCert.certPEM, leafCert.privateKeyPEM)
		}

		if params.leafConfigMapNamespace != "" && params.leafConfigMapName != "" {
			deployConfigMap(cs, params.leafConfigMapNamespace, params.leafConfigMapName, leafCert.certPEM)
		}
	}
}

func getParameters() Parameters {
	var params = Parameters{
		rootCAConfigMapNamespace: os.Getenv("ROOT_CA_CM_NAMESPACE"),
		rootCAConfigMapName:      os.Getenv("ROOT_CA_CM_NAME"),
		rootCASecretNamespace:    os.Getenv("ROOT_CA_SECRET_NAMESPACE"),
		rootCASecretName:         os.Getenv("ROOT_CA_SECRET_NAME"),
		rootCACertCN:             os.Getenv("ROOT_CA_CERT_CN"),

		leafConfigMapNamespace: os.Getenv("LEAF_CM_NAMESPACE"),
		leafConfigMapName:      os.Getenv("LEAF_CM_NAME"),
		leafSecretNamespace:    os.Getenv("LEAF_SECRET_NAMESPACE"),
		leafSecretName:         os.Getenv("LEAF_SECRET_NAME"),
		leafCertCN:             os.Getenv("LEAF_CERT_CN"),
		leafCertHosts:          splitOn(os.Getenv("LEAF_CERT_HOSTS"), ","),
	}

	var commonNamespace = os.Getenv("NAMESPACE")
	var rootCANamespace = os.Getenv("ROOT_CA_NAMESPACE")
	var leafNamespace = os.Getenv("LEAF_NAMESPACE")

	if rootCANamespace == "" {
		rootCANamespace = commonNamespace
	}
	if leafNamespace == "" {
		leafNamespace = commonNamespace
	}

	if rootCANamespace != "" {
		if params.rootCAConfigMapNamespace == "" {
			params.rootCAConfigMapNamespace = rootCANamespace
		}
		if params.rootCASecretNamespace == "" {
			params.rootCASecretNamespace = rootCANamespace
		}
	}
	if leafNamespace != "" {
		if params.leafConfigMapNamespace == "" {
			params.leafConfigMapNamespace = leafNamespace
		}
		if params.leafSecretNamespace == "" {
			params.leafSecretNamespace = leafNamespace
		}
	}

	if params.rootCACertCN == "" {
		params.rootCACertCN = "Root CA"
	}

	if params.leafCertCN == "" {
		params.leafCertCN = "Leaf"
	}

	return params
}

func splitOn(value string, delimiter string) []string {
	parts := strings.Split(value, delimiter)

	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	return parts
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

func deploySecret(clientset kubernetes.Clientset, namespace string, secretName string, certPEM string, keyPEM string) {
	log.Printf("Applying secret \"%s\" (namespace \"%s\")...\n", secretName, namespace)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte(certPEM),
			"tls.key": []byte(keyPEM),
		},
	}

	_, err := clientset.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	if err != nil {
		_, err = clientset.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
		if err != nil {
			log.Fatalf("Failed to create or update secret: %v", err)
		}
	}

	log.Printf("Secret \"%s\" (namespace \"%s\") successfully applied\n", secretName, namespace)
}

func deployConfigMap(clientset kubernetes.Clientset, namespace string, configMapName string, certPEM string) {
	log.Printf("Applying config map \"%s\" (namespace \"%s\")...\n", configMapName, namespace)

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

	log.Printf("Config map \"%s\" (namespace \"%s\") successfully applied\n", configMapName, namespace)
}
