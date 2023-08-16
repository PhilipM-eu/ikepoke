package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/monnand/dhkx"
	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

func GenECDH(algo int) ([]byte, *ecdh.PrivateKey, error) {
	var pubBytes []byte
	var privKey *ecdh.PrivateKey
	var curve ecdh.Curve
	//var prepend []byte
	//	privString := "701fb4308655b476b6789b7325f9ea8cddd16a58533ff6d9e60009464a5f9d54"
	//	privData, err := hex.DecodeString(privString)
	switch algo {

	case 19:
		curve = ecdh.P256()
		//prependString := "0000004800130000"
		//prepend, _ = hex.DecodeString(prependString)
	case 20:
		curve = ecdh.P384()
	case 21:
		curve = ecdh.P521()
	case 31:
		curve = ecdh.X25519()
	default:
		return nil, nil, errors.New("Unsupported ecdh curve")

	}

	privKey, err := curve.GenerateKey(rand.Reader)

	//	privKey, err = curve.NewPrivateKey(privData)
	if err != nil {
		return nil, nil, err
	}
	pub := privKey.PublicKey()
	if err != nil {
		return nil, nil, err

	}
	pubBytes = pub.Bytes()
	//publicKey needs to be without padding
	if len(pubBytes)%2 != 0 {
		pubBytes = pubBytes[1:]
	}
	//pubBytes = append(prepend, pubBytes...)
	return pubBytes, privKey, nil
}
func GenDH(algo int, keyLength int) ([]byte, *dhkx.DHGroup, *dhkx.DHKey, error) {
	if algo != 1 && algo != 2 && algo != 14 {
		return nil, nil, nil, errors.New("Cannot generate DH keys with the supplied algorithm id")
	}
	group, err := dhkx.GetGroup(algo)
	if err != nil {
		return nil, nil, nil, err
	}
	dhGroup := group
	priv, err := dhGroup.GeneratePrivateKey(nil)
	if err != nil {
		return nil, nil, nil, err
	}
	pub := priv.Bytes()
	//pad if necessary
	if len(pub) < keyLength {
		b := make([]byte, keyLength-len(pub))
		pub = append(b, pub...)
	}
	return pub, dhGroup, priv, nil
}

// DHExchange offers the generation of public keys as well as the calculation of shared secrets.
// Only the algorithm type and the public key are exposed.
type DHExchange struct {
	Algo        int
	dhGroup     *dhkx.DHGroup
	dhPrivKey   *dhkx.DHKey
	ecdhPrivKey *ecdh.PrivateKey
	ecdhCurve   *ecdh.Curve
	PubKey      []byte
	initialised bool
}

func (dhe *DHExchange) Init(algo int, keyLength int) error {
	dhe.Algo = algo
	var err error = nil
	switch dhe.Algo {

	case 1, 2, 14:

		dhe.PubKey, dhe.dhGroup, dhe.dhPrivKey, err = GenDH(algo, keyLength)
		if err != nil {
			return err
		}
		dhe.initialised = true
	case 19, 20, 21, 31:
		dhe.PubKey, dhe.ecdhPrivKey, err = GenECDH(algo)
		if err != nil {
			return err
		}
		dhe.initialised = true
	default:
		//only simulate a DH value with random values for scanning purposes
		// this works confimedly for the groups 5,15, 16,17, 18
		// an actual key exchagne is not possible with these groups
		pub := make([]byte, keyLength)
		rand.Read(pub)
		dhe.PubKey = pub
	}
	return nil
}
func (dhe *DHExchange) GenSharedSecret(remotePubKey []byte) ([]byte, error) {
	var sharedKey []byte = nil
	if !dhe.initialised {

		return nil, errors.New("Cannot perform shared secret generation - no keys were initialised")
	}
	switch dhe.Algo {
	case 1, 2, 14:

		publicKey := dhkx.NewPublicKey(remotePubKey)
		sessionKey, err := dhe.dhGroup.ComputeKey(publicKey, dhe.dhPrivKey)
		if err != nil {
			return nil, err
		}
		sharedKey = sessionKey.Bytes()
	case 19, 20, 21:
		// the ecdh library needs the remote public keys to be prepended with 0x04 to be able to use them for the NIST curves
		prepend := []byte{0x04}
		remotePubKey = append(prepend, remotePubKey...)
		fallthrough
	case 31:

		pubKey, err := dhe.ecdhPrivKey.Curve().NewPublicKey(remotePubKey)
		if err != nil {
			return nil, err
		}
		sharedKey, err = dhe.ecdhPrivKey.ECDH(pubKey)
		if err != nil {
			return nil, err
		}

	default:
		return nil, errors.New("Unsupported algorithm for performing shared key generation")
	}
	return sharedKey, nil
}

func GetKeys(encKeySize int, integritySize int, prfSize int, aead bool, keys *Keys) ([]byte, []byte, []byte, []byte, []byte, []byte, []byte) {
	//https://www.rfc-editor.org/rfc/rfc7296.html#section-2.13

	//used for deriving keys for child SAs
	// size is the same as skpi and skpr
	var skd []byte
	// used for initiator integrity protection
	var skai []byte
	// used for responder integrity protection
	var skar []byte

	// used for encryption/decryption of initiator messages
	// size depends on either the negotation or on the function used
	var skei []byte
	// used for dencryption/decryption of responder messages
	var sker []byte

	// used during generation of auth payload for inititator
	// size should be the same as the output size of the PRF (i.e. 512bit for sha2-512)
	var skpi []byte
	// used during generation of auth payload for responder
	//
	var skpr []byte

	skd = keys.GetKey(prfSize)
	if !aead {
		skai = keys.GetKey(integritySize)
		skar = keys.GetKey(integritySize)
	}
	skei = keys.GetKey(encKeySize)
	sker = keys.GetKey(encKeySize)

	skpi = keys.GetKey(prfSize)
	skpr = keys.GetKey(prfSize)
	return skd, skai, skar, skei, sker, skpi, skpr
}
func CalcAuthFromSharedSecret(prfAlgo byte, sharedSecret []byte, signedOctets []byte) []byte {
	pad := []byte("Key Pad for IKEv2")
	ikeKey := PRF(prfAlgo, sharedSecret, pad)
	authData := PRF(prfAlgo, ikeKey, signedOctets)
	return authData
}

// returns the ciphertext and the iv used
func EncryptPayload(algo byte, payload, key, extraData []byte) ([]byte, []byte) {
	ciphertext := make([]byte, 0)
	iv := make([]byte, 0)
	switch algo {
	// only difference between the aes gcm enc algos is the iv size that is used
	case IKEConst.ENCR_AES_GCM_12:

		ciphertext, iv = AESGCMEncrypt(payload, key, extraData, 12)
	case IKEConst.ENCR_AES_GCM_16:
		ciphertext, iv = AESGCMEncrypt(payload, key, extraData, 16)
	default:
		return nil, nil

	}
	return ciphertext, iv
}
func PadPlaintext(plaintext []byte, blocksize int) []byte {
	difference := len(plaintext) % blocksize
	fmt.Println(difference, len(plaintext))

	padLength := blocksize - difference
	if len(plaintext)%blocksize == 0 {
		padLength = 0
	}
	padding := make([]byte, padLength)
	padding = append(padding, byte(padLength))
	plaintext = append(plaintext, padding...)
	return plaintext

}
func unpadPlaintext(plaintext []byte) []byte {
	paddedLength := plaintext[len(plaintext)-1]
	return plaintext[:((len(plaintext)) - int(paddedLength))]

}
func AESGCMEncrypt(plaintext, key, extraData []byte, tagsize int) ([]byte, []byte) {
	//ivsize := 8
	c, _ := aes.NewCipher(key[:len(key)-4])
	gcm, _ := cipher.NewGCMWithTagSize(c, tagsize)
	iv := make([]byte, gcm.NonceSize()-4)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println(err)
	}
	nonce := append(key[len(key)-4:], iv...)
	//plaintext = padPlaintext(plaintext, 16)
	ciphertext := gcm.Seal(nil, nonce, plaintext, extraData)

	return ciphertext, iv
}
func AESGCMDecrypt(ciphertext, key, iv []byte, tagsize int) []byte {

	c, _ := aes.NewCipher(key[:len(key)-4])
	gcm, _ := cipher.NewGCMWithTagSize(c, tagsize)

	nonce := append(key[len(key)-4:], iv...)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	plaintext = unpadPlaintext(plaintext)
	return plaintext
}
func PRF(algo byte, key, data []byte) []byte {
	hashsum := make([]byte, 0)
	var hashfunction func() hash.Hash
	switch algo {
	//md5
	case IKEConst.PRF_HMAC_MD5:
		hashfunction = md5.New
		//sha1
	case IKEConst.PRF_HMAC_SHA1:
		hashfunction = sha1.New
	// sha2-256
	case IKEConst.PRF_HMAC_SHA2_256:
		hashfunction = sha256.New
		//sha2-384
	case IKEConst.PRF_HMAC_SHA2_384:
		hashfunction = sha512.New384
		// sha2-512
	case IKEConst.PRF_HMAC_SHA2_512:

		hashfunction = sha512.New
	default:

	}

	prf := hmac.New(hashfunction, key)
	prf.Write(data)
	hashsum = prf.Sum(nil)
	return hashsum
}

type Keys struct {
	skeyseed         []byte
	prfAlgo          byte
	keyingMaterial   []byte
	lastOutput       []byte
	currentIteration byte
	seed             []byte
}

func (k *Keys) Init(prfAlgo byte, nonceInitiator, nonceResponder, spiInitiator, spiResponder, dhSharedSecret []byte) {
	k.prfAlgo = prfAlgo
	noncesConcat := append(nonceInitiator, nonceResponder...)
	spiConcat := append(spiInitiator, spiResponder...)
	k.skeyseed = PRF(prfAlgo, noncesConcat, dhSharedSecret)
	k.currentIteration = 1
	k.seed = append(noncesConcat, spiConcat...)
	k.generateNewKeyingMaterial()
}
func (k *Keys) GetKey(length int) []byte {
	key := make([]byte, 0)
	// check whether the key needed is more than the keying material provided
	if length > len(k.keyingMaterial) {

		key = append(key, k.keyingMaterial...)
		for len(key) < length {
			k.generateNewKeyingMaterial()
			currentKeyLength := len(key)

			if length-currentKeyLength > len(k.keyingMaterial) {
				key = append(key, k.keyingMaterial...)
			} else {
				key = append(key, k.keyingMaterial[:length-currentKeyLength]...)
				if length-currentKeyLength < len(k.keyingMaterial) {
					k.keyingMaterial = k.keyingMaterial[length-currentKeyLength:]

				} else {

					k.keyingMaterial = make([]byte, 0)
				}
			}
		}
		// key needed is shorter
	} else {
		key = k.keyingMaterial[:length]
		if len(k.keyingMaterial) > length {

			k.keyingMaterial = k.keyingMaterial[length:]
		} else {
			k.keyingMaterial = make([]byte, 0)
			k.generateNewKeyingMaterial()
		}

	}
	return key
}
func (k *Keys) generateNewKeyingMaterial() {
	seedMat := append(k.lastOutput, k.seed...)
	seedMat = append(seedMat, k.currentIteration)
	output := PRF(k.prfAlgo, k.skeyseed, seedMat)
	k.keyingMaterial = output
	k.lastOutput = output
	k.currentIteration++
}
