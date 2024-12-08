package cryptotest

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func ReadPrivedKey(filename string) (*rsa.PrivateKey, error) {
	var key *rsa.PrivateKey

	KeyFile, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error when read priv key file %w", err)
	}
	defer KeyFile.Close()

	pemfileinfo, _ := KeyFile.Stat()
	pembytes := make([]byte, pemfileinfo.Size())
	buffer := bufio.NewReader(KeyFile)
	_, err = buffer.Read(pembytes)
	if err != nil {
		return nil, fmt.Errorf("error when read priv key file %w", err)
	}
	block, _ := pem.Decode(pembytes)

	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("err when parse priv key %w", err)
	}
	return key, nil
}

func ReadPublicKey(filename string) (*rsa.PublicKey, error) {
	var key *rsa.PublicKey

	KeyFile, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error when read priv key file %w", err)
	}
	defer KeyFile.Close()

	pemfileinfo, _ := KeyFile.Stat()
	pembytes := make([]byte, pemfileinfo.Size())
	buffer := bufio.NewReader(KeyFile)
	_, err = buffer.Read(pembytes)
	if err != nil {
		return nil, fmt.Errorf("error when read priv key file %w", err)
	}
	block, _ := pem.Decode(pembytes)

	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("err when parse public key %w", err)
	}
	return key, nil
}

func GenerateKeys() error {
	var err error
	var pemPrivFile, pemPubFile *os.File
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey

	pemPrivFile, err = os.Create("private_key.pem")
	if err != nil {
		return fmt.Errorf("error when create private pem file %w", err)
	}
	defer pemPrivFile.Close()

	pemPubFile, err = os.Create("public_key.pem")
	if err != nil {
		return fmt.Errorf("error when create public pem file %w", err)
	}
	defer pemPubFile.Close()

	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("error when generate priv key %w", err)
	}

	publicKey = &privateKey.PublicKey

	blockPriv := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	blockPub := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}

	if err := pem.Encode(pemPrivFile, blockPriv); err != nil {
		return fmt.Errorf("error when write pem format priv key to file %w", err)
	}

	if err := pem.Encode(pemPubFile, blockPub); err != nil {
		return fmt.Errorf("error when write pem format pib key to file %w", err)
	}

	return nil
}
