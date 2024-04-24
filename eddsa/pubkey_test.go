package eddsa

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"
)

func TestEddsaPubkey(t *testing.T) {
	pubKeyBytes, err := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f249")
	assert.NoError(t, err)
	pbk, err := edwards.ParsePubKey(pubKeyBytes)
	assert.NoError(t, err)

	pbkBytes := pbk.Serialize()
	assert.Equal(t, pbkBytes, pubKeyBytes)

	pk2 := edwards.NewPublicKey(pbk.X, pbk.Y)
	assert.Equal(t, pbk, pk2)
}
