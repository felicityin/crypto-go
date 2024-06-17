package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	ecies "github.com/ecies/go/v2"
	"github.com/stretchr/testify/assert"
)

func TestEcdsaSign(t *testing.T) {
	// encryption and decryption

	k, err := ecies.GenerateKey()
	assert.NoError(t, err)

	text := []byte("THIS IS THE TEST")
	ciphertext, err := ecies.Encrypt(k.PublicKey, text)
	assert.NoError(t, err)

	plaintext, err := ecies.Decrypt(k, ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, text, plaintext)

	// sign and verify

	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey(*k.PublicKey),
		D:         k.D,
	}

	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))

	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	assert.NoError(t, err)

	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], sig)
	assert.True(t, valid)
}
