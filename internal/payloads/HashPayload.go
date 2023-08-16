package payloads

import (
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type HashPayload struct {
	Header   PayloadHeader
	HashData []byte
}

func NewHashPayload(hashData []byte) *HashPayload {
	payload := HashPayload{
		Header:   NewPayloadHeader(uint16(len(hashData))),
		HashData: hashData,
	}
	return &payload

}
func (h *HashPayload) Serialize() []byte {
	serialized := h.Header.Serialize()
	serialized = append(serialized, h.HashData...)
	return serialized
}
func (h *HashPayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	h.Header = header
	if len(input) < int(h.Header.Length) {
		return errors.New("Input too short to deserialize hash payload")
	}
	h.HashData = input[4:h.Header.Length]

	return nil
}
func (h *HashPayload) GetLength() uint16 {
	return h.Header.Length

}
func (h *HashPayload) GetType() byte {
	return IKEConst.H
}
func (h *HashPayload) GetNextPayload() byte {
	return h.Header.NextPayload
}
func (h *HashPayload) SetNextPayload(nextPayload byte) {

	h.Header.NextPayload = nextPayload
}
