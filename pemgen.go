package pemgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

func GenRandKey(bitsize int64) (*rsa.PrivateKey, error) {
	r := rand.Reader
	key, err := GenKey(r, bitsize)
	if err != nil {
		err = fmt.Errorf("error calling genkey w/ rand.reader: %v", err)
	}

	return key, err
}

func GenKey(r io.Reader, bitsize int64) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(r, int(bitsize))
	if err != nil {
		return nil, fmt.Errorf("error calling rsa.generatekey: %v", err)
	}

	return key, nil
}

func WritePrivateKey(w io.Writer, key *rsa.PrivateKey) error {
	privkey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err := pem.Encode(w, privkey)
	if err != nil {
		return fmt.Errorf("error calling pem.encode: %v", err)
	}

	return nil
}

func WritePublicKey(w io.Writer, key *rsa.PublicKey) error {
	pemkey := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(key),
	}

	err := pem.Encode(w, pemkey)
	if err != nil {
		return fmt.Errorf("error calling pem.encode: %v", err)
	}

	return nil
}
