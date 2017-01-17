package jwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ErrNotECKey error for invalid EC key, implements the ErrKey interface
type ErrNotECKey struct {
	public bool
	key    interface{}
}

func (e ErrNotECKey) Error() string {
	if e.public {
		return fmt.Sprintf("Key is not a valid ECDSA public key: %#v", e.key)
	}
	return fmt.Sprintf("Key is not a valid ECDSA private key: %#v", e.key)
}

// Key returns the key to complete the ErrKey interface
func (e ErrNotECKey) Key() interface{} {
	return e.key
}

// ErrNotECPublicKey custom error for EC public key
func ErrNotECPublicKey(key interface{}) ErrKey {
	return ErrNotECKey{public: true, key: key}
}

// ErrNotECPrivateKey custom error for EC public key
func ErrNotECPrivateKey(key interface{}) ErrKey {
	return ErrNotECKey{public: false, key: key}
}

// ParseECPrivateKeyFromPEM parse PEM encoded Elliptic Curve Private Key Structure
func ParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyNotPEMEncoded{key: key}
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		return nil, err
	}

	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, ErrNotECPrivateKey(parsedKey)
	}
	return pkey, nil
}

// ParseECPublicKeyFromPEM parse PEM encoded PKCS1 or PKCS8 public key
func ParseECPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error) {
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

	var pkey *ecdsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return nil, ErrNotECPublicKey(parsedKey)
	}
	return pkey, nil
}
