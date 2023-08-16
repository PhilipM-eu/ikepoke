package payloads

import (
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type EncryptedPayload struct {
	Header               PayloadHeader
	ivLength             int // is equal to the blocksize of the encryption algo
	InitializationVector []byte
	EncryptedData        []byte
	ChecksumData         []byte // is computed over the encrypted message and not the plaintext
	ChecksumLength       int    // depends on the integrity algorithm in use, is 0 when AEAD is in use
}

func NewEncryptedPayload(initializationVector, encryptedData, checksumData []byte, payloadTypeEncData byte) *EncryptedPayload {
	encPayload := EncryptedPayload{
		Header: NewPayloadHeader(uint16(
			len(initializationVector) + len(encryptedData) + len(checksumData),
		)),
		ivLength:             len(initializationVector),
		InitializationVector: initializationVector,
		EncryptedData:        encryptedData,
		ChecksumData:         checksumData,
		ChecksumLength:       len(checksumData),
	}
	encPayload.Header.NextPayload = payloadTypeEncData
	return &encPayload

}
func NewEncryptedPayloadEmpty(length uint16, payloadTypeEncData byte) *EncryptedPayload {

	encPayload := EncryptedPayload{
		Header: NewPayloadHeader(uint16(
			length,
		)),
	}
	encPayload.Header.NextPayload = payloadTypeEncData
	return &encPayload

}
func (e *EncryptedPayload) AddData(iv, encryptedData, checksumData []byte) {
	e.ivLength = len(iv)
	e.InitializationVector = iv
	e.EncryptedData = encryptedData
	e.ChecksumData = checksumData
	e.ChecksumLength = len(checksumData)

}
func (e *EncryptedPayload) Serialize() []byte {
	serialized := e.Header.Serialize()
	serialized = append(serialized, e.InitializationVector...)
	serialized = append(serialized, e.EncryptedData...)
	// if AEAD algo is in use, no integrity function is needed/used
	if e.ChecksumLength > 0 {
		serialized = append(serialized, e.ChecksumData...)
	}
	return serialized
}
func (e *EncryptedPayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	e.Header = header
	if len(input) < int(e.Header.Length) {
		return errors.New("Can not parse encrypted payload - input too short for supposed length")
	}
	e.EncryptedData = input[4 : int(e.Header.Length)-e.ChecksumLength]
	if e.ChecksumLength > 0 {
		e.ChecksumData = input[int(e.Header.Length)-e.ChecksumLength : e.Header.Length]
	}
	return nil
}
func (e *EncryptedPayload) GetLength() uint16 {
	return e.Header.Length
}
func (e *EncryptedPayload) GetType() byte {
	return IKEConst.ENCAndAUTH
}
func (e *EncryptedPayload) GetNextPayload() byte {
	return e.Header.NextPayload
}
func (e *EncryptedPayload) SetNextPayload(payloadType byte) {
	e.Header.NextPayload = payloadType
}
