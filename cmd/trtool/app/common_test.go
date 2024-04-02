package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadChain(t *testing.T) {
	var p = "../../../test_data/tsa-chain.pem"

	certs, err := loadChain(p, false)

	assert.Nil(t, err)
	assert.Equal(t, 3, len(certs))
	assert.Equal(t, "TSA Timestamping", certs[0].Subject.CommonName)
	assert.Equal(t, "TSA intermediate", certs[1].Subject.CommonName)
	assert.Equal(t, "Root", certs[2].Subject.CommonName)

	// Test order chain
	certs[0], certs[2] = certs[2], certs[0]
	assert.Equal(t, "Root", certs[0].Subject.CommonName)
	assert.Equal(t, "TSA Timestamping", certs[2].Subject.CommonName)

	ordered, err := orderCertChain(certs)

	assert.Nil(t, err)
	assert.Equal(t, certs[2].Subject.CommonName, ordered[0].Subject.CommonName)
	assert.Equal(t, certs[1].Subject.CommonName, ordered[1].Subject.CommonName)
	assert.Equal(t, certs[0].Subject.CommonName, ordered[2].Subject.CommonName)
}
