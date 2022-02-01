package main

import (
	"fmt"
	"os"

	"github.com/phantommachine/pemgen"
)

func main() {
	mykey, err := pemgen.GenRandKey(4098)
	if err != nil {
		panic(fmt.Errorf("error calling pemgen.genrandkey: %v", err))
	}

	prf, err := os.Create("rsa_key.priv")
	if err != nil {
		panic(fmt.Errorf("error creating private key file: %v", err))
	}

	puf, err := os.Create("rsa_key.pub")
	if err != nil {
		panic(fmt.Errorf("error creating public key file: %v", err))
	}

	err = pemgen.WritePrivateKey(prf, mykey)
	if err != nil {
		panic(fmt.Errorf("error creating public key file: %v", err))
	}

	err = pemgen.WritePublicKey(puf, &mykey.PublicKey)
	if err != nil {
		panic(fmt.Errorf("error creating public key file: %v", err))
	}
}
