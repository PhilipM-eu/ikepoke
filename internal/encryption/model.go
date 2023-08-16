package encryption

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type PRFAlgorithm struct {
	ID         uint16
	Function   func() hash.Hash
	OutputSize int
}

func GetPRF(algoID uint16) *PRFAlgorithm {
	prf := PRFAlgorithm{ID: algoID}
	switch algoID {

	case IKEConst.PRF_HMAC_MD5:
		prf.Function = md5.New
		prf.OutputSize = 128
		//sha1
	case IKEConst.PRF_HMAC_SHA1:
		prf.Function = sha1.New
		prf.OutputSize = 160
	// sha2-256
	case IKEConst.PRF_HMAC_SHA2_256:
		prf.Function = sha256.New
		prf.OutputSize = 256
		//sha2-384
	case IKEConst.PRF_HMAC_SHA2_384:
		prf.Function = sha512.New384
		prf.OutputSize = 384
		// sha2-512
	case IKEConst.PRF_HMAC_SHA2_512:

		prf.Function = sha512.New
		prf.OutputSize = 512
	default:

	}
	return &prf
}

type EncAlgorithm struct {
	ID        uint16
	AEAD      bool
	keyLength int
	ivLength  int
}
