package payloads

import (
	"encoding/binary"
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type KeyExchangePayload struct {
	Header   PayloadHeader
	DHGroup  uint16
	Reserved uint16
	Data     []byte
	IKEv1    bool
}

func NewKeyExchangePayload(dhGroup uint16, data []byte, ikev1 bool) *KeyExchangePayload {
	length := 0
	if !ikev1 {
		length = 4
	}
	kexPayload := KeyExchangePayload{
		Header:   NewPayloadHeader(uint16(length + len(data))),
		DHGroup:  dhGroup,
		Reserved: 0,
		Data:     data,
		IKEv1:    ikev1,
	}
	return &kexPayload
}
func (k *KeyExchangePayload) Serialize() []byte {
	serialized := k.Header.Serialize()
	if !k.IKEv1 {
		// new slice necessary as we need to set the dhgroup and reserved

		kexSerialized := make([]byte, 4)
		binary.BigEndian.PutUint16(kexSerialized[0:2], k.DHGroup)
		binary.BigEndian.PutUint16(kexSerialized[2:4], k.Reserved)
		serialized = append(serialized, kexSerialized...)
	}
	serialized = append(serialized, k.Data...)
	return serialized
}
func (k *KeyExchangePayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	k.Header = header

	if len(input) < int(k.Header.Length) {
		return errors.New("Input too short to deserialize KEX  payload")
	}
	if k.IKEv1 {
		k.Data = input[4:k.Header.Length]
	} else {
		if len(input) < 8 {
			return errors.New("Input too short to deserialize KEX  payload")
		}
		k.DHGroup = binary.BigEndian.Uint16(input[4:6])
		k.Reserved = binary.BigEndian.Uint16(input[6:8])
		k.Data = input[8:k.Header.Length]

	}
	return nil
}
func (k *KeyExchangePayload) GetLength() uint16 {
	return k.Header.Length
}
func (k *KeyExchangePayload) GetType() byte {
	if k.IKEv1 {
		return IKEConst.IKEv1_KE
	}
	return IKEConst.KE
}
func (k *KeyExchangePayload) GetNextPayload() byte {
	return k.Header.NextPayload
}
func (k *KeyExchangePayload) SetNextPayload(payloadType byte) {
	k.Header.NextPayload = payloadType

}
