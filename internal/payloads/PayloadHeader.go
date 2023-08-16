package payloads

import (
	"encoding/binary"
	"errors"
)

type PayloadHeader struct {
	NextPayload     byte
	CritAndReserved byte
	Length          uint16
}

func (h *PayloadHeader) Serialize() []byte {
	serialized := make([]byte, 4)
	serialized[0] = h.NextPayload
	serialized[1] = h.CritAndReserved
	binary.BigEndian.PutUint16(serialized[2:4], h.Length)
	return serialized
}

func (h *PayloadHeader) DeSerialize(input []byte) error {
	if len(input) < 4 {
		return errors.New("Input too short to deserialize payload header")
	}
	h.NextPayload = input[0]
	h.CritAndReserved = input[1]
	h.Length = binary.BigEndian.Uint16(input[2:4])
	return nil
}

// New payload is always initialized as 0, i.e. under the assumption that this payload is the last in the list
func NewPayloadHeader(lengthOfAdditionalData uint16) PayloadHeader {
	header := PayloadHeader{
		NextPayload:     0,
		CritAndReserved: 0,
		Length:          4 + lengthOfAdditionalData,
	}
	return header
}
