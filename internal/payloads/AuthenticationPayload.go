package payloads

import (
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type AuthenticationPayload struct {
	Header     PayloadHeader
	AuthMethod byte
	Reserved   []byte // 3 bytes in size
	Data       []byte
}

func NewAuthenticationPayload(authMethod byte, data []byte) *AuthenticationPayload {
	auth := AuthenticationPayload{
		Header:     NewPayloadHeader(uint16(4 + len(data))),
		AuthMethod: authMethod,
		Reserved:   make([]byte, 3),
		Data:       data,
	}
	return &auth
}
func (a *AuthenticationPayload) Serialize() []byte {
	serialized := a.Header.Serialize()
	serialized = append(serialized, a.AuthMethod)
	serialized = append(serialized, a.Reserved...)
	serialized = append(serialized, a.Data...)
	return serialized
}
func (a *AuthenticationPayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	a.Header = header
	if len(input) < int(a.Header.Length) {
		return errors.New("Could not parse authentication payload - input too short for supposed length ")
	}
	a.AuthMethod = input[4]
	a.Reserved = input[5:8]
	a.Data = input[8:a.Header.Length]
	return nil
}
func (a *AuthenticationPayload) GetLength() uint16 {
	return a.Header.Length
}
func (a *AuthenticationPayload) GetType() byte {
	return IKEConst.AUTH
}
func (a *AuthenticationPayload) GetNextPayload() byte {
	return a.Header.NextPayload
}
func (a *AuthenticationPayload) SetNextPayload(payloadType byte) {
	a.Header.NextPayload = payloadType
}
