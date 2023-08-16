package payloads

import (
	"encoding/binary"
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type IdentificationPayload struct {
	Header    PayloadHeader
	IDType    byte
	Reserved  []byte //3bytes in size
	Data      []byte
	Initiator bool // needed for the difference between IDi and IDr - will not be serialized
}
type IdentificationPayloadIKEv1 struct {
	Header     PayloadHeader
	IDType     byte
	ProtocolID byte
	Port       uint16
	Data       []byte
}

func (i *IdentificationPayloadIKEv1) Serialize() []byte {
	serialized := i.Header.Serialize()
	serialized = append(serialized, i.IDType)
	serialized = append(serialized, i.ProtocolID)
	portSerialized := make([]byte, 2)
	binary.BigEndian.PutUint16(portSerialized, i.Port)
	serialized = append(serialized, portSerialized...)
	serialized = append(serialized, i.Data...)

	return serialized
}
func NewIdentificationPayloadIKEv1(idType, protocolID byte, port uint16, data []byte) *IdentificationPayloadIKEv1 {
	idPayload := IdentificationPayloadIKEv1{
		Header:     NewPayloadHeader(uint16(4 + len(data))),
		IDType:     idType,
		ProtocolID: protocolID,
		Port:       port,
		Data:       data,
	}
	return &idPayload
}

// TODO add how the difference between IDi and IDr is calculated from deserialize
func (i *IdentificationPayloadIKEv1) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	i.Header = header
	if len(input) < int(i.Header.Length) {
		return errors.New("Can not deserialize identification payload - Input too short for supposed length")
	}
	i.IDType = input[4]
	i.ProtocolID = input[5]
	i.Port = binary.BigEndian.Uint16(input[6:8])
	i.Data = input[8:i.Header.Length]

	return nil
}
func (i *IdentificationPayloadIKEv1) GetLength() uint16 {
	return i.Header.Length
}
func (i *IdentificationPayloadIKEv1) GetType() byte {
	return IKEConst.ID
}
func (i *IdentificationPayloadIKEv1) GetNextPayload() byte {
	return i.Header.NextPayload
}
func (i *IdentificationPayloadIKEv1) SetNextPayload(payloadType byte) {
	i.Header.NextPayload = payloadType
}
func (i *IdentificationPayload) Serialize() []byte {
	serialized := i.Header.Serialize()
	serialized = append(serialized, i.IDType)
	serialized = append(serialized, i.Reserved...)
	serialized = append(serialized, i.Data...)

	return serialized
}
func (i *IdentificationPayload) SerializePayload() []byte {
	serialized := make([]byte, 1)
	serialized[0] = i.IDType
	serialized = append(serialized, i.Reserved...)
	serialized = append(serialized, i.Data...)
	return serialized
}
func NewIdentificationPayload(idType byte, data []byte, initiator bool) *IdentificationPayload {
	idPayload := IdentificationPayload{
		Header:    NewPayloadHeader(uint16(4 + len(data))),
		IDType:    idType,
		Reserved:  make([]byte, 3),
		Data:      data,
		Initiator: initiator,
	}
	return &idPayload
}

// TODO add how the difference between IDi and IDr is calculated from deserialize
func (i *IdentificationPayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	i.Header = header
	if len(input) < int(i.Header.Length) {
		return errors.New("Can not deserialize identification payload - Input too short for supposed length")
	}
	i.IDType = input[4]
	i.Reserved = input[5:8]
	i.Data = input[8:i.Header.Length]

	return nil
}
func (i *IdentificationPayload) GetLength() uint16 {
	return i.Header.Length
}
func (i *IdentificationPayload) GetType() byte {
	if i.Initiator {
		return IKEConst.IDi
	} else {
		return IKEConst.IDr
	}
}
func (i *IdentificationPayload) GetNextPayload() byte {
	return i.Header.NextPayload
}
func (i *IdentificationPayload) SetNextPayload(payloadType byte) {
	i.Header.NextPayload = payloadType
}
