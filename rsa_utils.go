package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ErrKeyNotPEMEncoded error when key not PEM encoded
type ErrKeyNotPEMEncoded struct {
	key interface{}
}

// Key method to implement the ErrKey interface
func (e ErrKeyNotPEMEncoded) Key() interface{} {
	return e.key
}

func (e ErrKeyNotPEMEncoded) Error() string {
	return fmt.Sprintf("Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key: %#v", e.key)
}

// ErrNotRSAPrivateKey error when key not valid private RSA
type ErrNotRSAPrivateKey struct {
	key interface{}
}

// Key method to implement the ErrKey interface
func (e ErrNotRSAPrivateKey) Key() interface{} {
	return e.key
}

func (e ErrNotRSAPrivateKey) Error() string {
	return fmt.Sprintf("Key is not a valid RSA private key: %#v", e.key)
}

// ErrNotRSAPublicKey error when key not valid private RSA
type ErrNotRSAPublicKey struct {
	key interface{}
}

// Key method to implement the ErrKey interface
func (e ErrNotRSAPublicKey) Key() interface{} {
	return e.key
}

func (e ErrNotRSAPublicKey) Error() string {
	return fmt.Sprintf("Key is not a valid RSA public key: %#v", e.key)
}

// var (
// ErrKeyNotPEMEncoded = errors.New("Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
// ErrNotRSAPrivateKey = errors.New("Key is not a valid RSA private key")
// ErrNotRSAPublicKey = errors.New("Key is not a valid RSA public key")
// )

// ParseRSAPrivateKeyFromPEM Parse PEM encoded PKCS1 or PKCS8 private key
func ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyNotPEMEncoded{key: key}
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, ErrNotRSAPrivateKey{parsedKey}
	}

	return pkey, nil
}

// ParseRSAPublicKeyFromPEM parse PEM encoded PKCS1 or PKCS8 public key
func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyNotPEMEncoded{key: key}
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, ErrNotRSAPublicKey{key: key}
	}

	return pkey, nil
}
