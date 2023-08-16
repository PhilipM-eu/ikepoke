package payloads

import (
	"encoding/binary"
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type TransformPayload struct {
	Header               PayloadHeader
	IKEv1                bool
	TransformType        byte
	Reserved             byte
	TransformID          uint16
	IKEv1TransformNumber byte
	IKEv1ID              byte
	IKEv1Reserved        uint16
	Attributes           []TransformAttribute
}

type TransformAttribute struct {
	Format byte
	Type   byte
	Length uint16
	Value  []byte
}

func NewTransformPayloadIKEv2(transformType byte, id uint16) *TransformPayload {
	var transform TransformPayload

	transform = TransformPayload{
		Header:        NewPayloadHeader(4),
		TransformType: transformType,
		Reserved:      0,
		TransformID:   id,
		IKEv1:         false,
	}

	return &transform
}

func NewTransformPayloadIKEv1(transformNumber byte, ikev1ID byte) *TransformPayload {
	var transform TransformPayload

	transform = TransformPayload{
		Header:               NewPayloadHeader(4),
		IKEv1:                true,
		IKEv1TransformNumber: transformNumber,
		IKEv1ID:              ikev1ID,
		IKEv1Reserved:        0,
	}

	return &transform
}
func (t *TransformPayload) AddAttribute(format, attributeType byte, value []byte) {
	attribute := TransformAttribute{Format: format, Type: attributeType, Value: value}
	length := 2 + len(value)
	if format == 0x00 {
		attribute.Length = uint16(len(value))
		length += 2
	}
	t.Attributes = append(t.Attributes, attribute)
	t.Header.Length += uint16(length)
}
func (a *TransformAttribute) Serialize() []byte {
	serialized := make([]byte, 2)
	serialized[0] = a.Format
	serialized[1] = a.Type
	if a.Format == 0x00 {
		// enlarge the slice cap to 4
		serialized = append(serialized, make([]byte, 2)...)
		binary.BigEndian.PutUint16(serialized[2:4], a.Length)
		serialized = append(serialized, a.Value...)

	} else if a.Format == IKEConst.ATTR_TV {

		serialized = append(serialized, a.Value[:2]...)
	}
	return serialized
}
func (a *TransformAttribute) DeSerialize(input []byte) error {
	a.Format = input[0]
	a.Type = input[1]
	if a.Format == 0x00 {
		a.Length = binary.BigEndian.Uint16(input[2:4])
		a.Value = input[4 : 4+int(a.Length)]

	} else if a.Format == IKEConst.ATTR_TV {

		a.Value = input[2:4]

	} else {
		return errors.New("Unknown attribute type")
	}
	return nil
}
func (t *TransformPayload) serializeIKEv2() []byte {

	transformSerialized := make([]byte, 4)
	transformSerialized[0] = t.TransformType
	transformSerialized[1] = t.Reserved
	binary.BigEndian.PutUint16(transformSerialized[2:4], t.TransformID)
	return transformSerialized

}
func (t *TransformPayload) serializeIKEv1() []byte {

	transformSerialized := make([]byte, 4)
	transformSerialized[0] = t.IKEv1TransformNumber
	transformSerialized[1] = t.IKEv1ID
	binary.BigEndian.PutUint16(transformSerialized[2:4], t.IKEv1Reserved)

	return transformSerialized
}
func (t *TransformPayload) Serialize() []byte {
	serialized := t.Header.Serialize()
	var transformSerialized []byte
	if t.IKEv1 {
		transformSerialized = t.serializeIKEv1()
	} else {

		transformSerialized = t.serializeIKEv2()
	}

	for _, attribute := range t.Attributes {
		transformSerialized = append(transformSerialized, attribute.Serialize()...)

	}
	serialized = append(serialized, transformSerialized...)
	return serialized
}
func (t *TransformPayload) deSerializeIKEv2(input []byte) error {
	if len(input) < 4 {
		return errors.New("Cannot parse iekv2 transform payload - input length too short")

	}

	t.TransformType = input[0]
	t.Reserved = input[1]
	t.TransformID = binary.BigEndian.Uint16(input[2:4])
	return nil
}

func (t *TransformPayload) deSerializeIKEv1(input []byte) error {

	if len(input) < 4 {
		return errors.New("Cannot parse ikev1 transform payload - input length too short")

	}
	t.IKEv1TransformNumber = input[0]
	t.IKEv1ID = input[1]
	t.Reserved = 0
	return nil
}

func (t *TransformPayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return nil
	}
	t.Header = header
	if len(input) < int(t.Header.Length) || len(input) < 8 {
		return errors.New("Can not parse transform payload - input too short for supposed length")
	}
	currentPosition := 4

	if t.IKEv1 {

		err = t.deSerializeIKEv1(input[currentPosition:])
		if err != nil {
			return err
		}
	} else {
		err = t.deSerializeIKEv2(input[currentPosition:])
		if err != nil {
			return err
		}
	}

	currentPosition += 4
	for currentPosition+3 < int(t.Header.Length) {
		attribute := TransformAttribute{
			Format: input[currentPosition],
			Type:   input[currentPosition+1],
			Value:  input[currentPosition+2 : currentPosition+4],
			Length: 0,
		}
		if attribute.Format == 0x00 {
			attribute.Length = binary.BigEndian.Uint16(input[currentPosition+2 : currentPosition+4])
			attribute.Value = input[currentPosition+4 : currentPosition+4+int(attribute.Length)]

		}
		currentPosition += 4 + int(attribute.Length)
		t.Attributes = append(t.Attributes, attribute)
	}

	return nil
}
func (t *TransformPayload) GetLength() uint16 {

	return t.Header.Length
}
func (t *TransformPayload) GetType() byte { return IKEConst.T }
func (t *TransformPayload) GetNextPayload() byte {
	return t.Header.NextPayload

}
func (t *TransformPayload) SetNextPayload(payloadType byte) {
	t.Header.NextPayload = payloadType
}
