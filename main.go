package main

import (
	"crypto/rsa"
	"log"

	cryptotest "netzen.dev/cyrpto_test/internal"
)

func main() {
	var privkey *rsa.PrivateKey
	var consumer *cryptotest.Consumer
	filename := "privKey"

	err := cryptotest.GenerateKeys(filename)
	if err != nil {
		log.Fatalf("error when get consumer %v", err)
	}

	consumer, err = cryptotest.NewConsumer(filename)
	if err != nil {
		log.Fatalf("error when get consumer %v", err)
	}
	privkey, err = consumer.ReadPrivKey()
	if err != nil {
		log.Fatalf("errr getting priv key %v", err)
	}

	// var privkey *rsa.PrivateKey
	// var err error
	// privkey, err = cryptotest.ReadPrivedKey("/home/netzen/.ssh/id_rsa")
	// if err != nil {
	// 	log.Fatalf("error when open key file %v", err)
	// }
	// log.Println(privkey)

	log.Println(privkey)

}
