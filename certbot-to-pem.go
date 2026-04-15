package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/go-jose/go-jose/v4"
)

func main() {
	configPath := "/etc/letsencrypt"
	flag.Func("path", "Certbot configuration path", func(s string) error {
		_, err := os.Stat(s)
		if err == nil {
			configPath = s
		}
		return err
	})
	server := flag.String("server", "acme-v02.api.letsencrypt.org/directory", "Let's Encrypt server")
	flag.Parse()

	basePath := filepath.Join(configPath, "accounts", *server)
	items, err := os.ReadDir(basePath)
	if err != nil {
		log.Println("failed to list configuraion directory:", err)
	}
	if len(items) != 1 {
		log.Fatalf("found %d accounts, expects 1 account", len(items))
	}
	acctPath := filepath.Join(basePath, items[0].Name())

	regrData, err := os.ReadFile(filepath.Join(acctPath, "regr.json"))
	if err != nil {
		log.Fatalln("error reading account information:", err)
	}
	var regr struct {
		URI  string `json:"uri"`
		Body struct {
			Contact []string `json:"contact"`
		} `json:"body"`
	}
	if err := json.Unmarshal(regrData, &regr); err != nil {
		log.Fatalln("error reading account information:", err)
	}

	privKeyData, err := os.ReadFile(filepath.Join(acctPath, "private_key.json"))
	if err != nil {
		log.Fatalln("error reading private key:", err)
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(privKeyData); err != nil {
		log.Fatalln("error reading private key:", err)
	}
	if !jwk.Valid() {
		log.Fatalln("found invalid private key")
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		log.Fatalln("error computing private key thumbprint:", err)
	}

	var contacts []string
	for _, contact := range regr.Body.Contact {
		if strings.HasPrefix(contact, "mailto:") {
			contacts = append(contacts, contact[len("mailto:"):])
		}
	}

	if term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Printf("Account details for server https://%s:\n", *server)
		fmt.Println("  Account URL:", regr.URI)
		fmt.Println("  Account Thumbprint:", base64.RawURLEncoding.EncodeToString(tp))
		if len(contacts) > 0 {
			fmt.Println("  Email contact:", strings.Join(contacts, ", "))
		} else {
			fmt.Println("  Email contact: none")
		}
	}

	var b pem.Block
	switch k := jwk.Key.(type) {
	case *rsa.PrivateKey:
		b.Type = "RSA PRIVATE KEY"
		b.Bytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			log.Fatalln("error encoding private key:", err)
		}
		b.Type = "EC PRIVATE KEY"
		b.Bytes = der
	}
	pem.Encode(os.Stdout, &b)
}
