package cryptotest

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

type Consumer struct {
	file *os.File
	// добавляем Reader в Consumer
	// reader  *bufio.Reader
	Scanner *bufio.Scanner
}

func NewConsumer(filename string) (*Consumer, error) {
	file, err := os.OpenFile(filename, os.O_RDONLY, 0666)
	if err != nil {
		return nil, err
	}

	return &Consumer{
		file: file,
		// создаём новый Reader
		Scanner: bufio.NewScanner(file),
	}, nil
}

func (c *Consumer) ReadPrivKey() (*rsa.PrivateKey, error) {
	var key *rsa.PrivateKey
	var err error
	date := make([]byte, 0, 2048)
	scanner := c.Scanner
	for scanner.Scan() {
		date = append(date, scanner.Bytes()...)
	}
	log.Println(scanner.Bytes())
	block, _ := pem.Decode(date)

	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing public key")
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("err when parse priv key %w", err)
	}
	return key, nil
}

func (c *Consumer) ReadPubKey() (*rsa.PublicKey, error) {
	var pub any
	var err error
	scanner := c.Scanner
	for scanner.Scan() {
		// преобразуем данные из JSON-представления в структуру
		block, _ := pem.Decode([]byte(scanner.Bytes()))
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("err when parse pub key %w", err)
		}
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("only rsa pubkey allowed")
	}
}

func ReadPrivedKey(filename string) (*rsa.PrivateKey, error) {
	var key *rsa.PrivateKey

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error when read priv key file %w", err)
	}
	log.Println(string(data))
	block, _ := pem.Decode(data)

	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("err when parse priv key %w", err)
	}
	return key, nil
}

func GenerateKeys(filename string) error {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	os.WriteFile("privKey", x509.MarshalPKCS1PrivateKey(privateKey), 0666)
	return nil
}
