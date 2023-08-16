package payloads

import (
	"encoding/binary"
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type DeletePayload struct {
	Header       PayloadHeader
	ProtocolID   byte
	SPISize      byte
	NumberOfSPIs uint16
	SPIs         []byte
}

func NewDeletePayload(protocolID, spiSize byte, numberOfSPIs uint16, spis []byte) *DeletePayload {
	delPayload := DeletePayload{
		Header:       NewPayloadHeader(uint16(4 + len(spis))),
		ProtocolID:   protocolID,
		SPISize:      spiSize,
		NumberOfSPIs: numberOfSPIs,
		SPIs:         spis,
	}
	return &delPayload
}
func (p *DeletePayload) Serialize() []byte {
	serialized := p.Header.Serialize()
	deleteSerialized := make([]byte, 4)
	deleteSerialized[0] = p.ProtocolID
	deleteSerialized[1] = p.SPISize
	binary.BigEndian.PutUint16(deleteSerialized[2:4], p.NumberOfSPIs)
	serialized = append(serialized, deleteSerialized...)
	serialized = append(serialized, p.SPIs...)
	return serialized

}
func (p *DeletePayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {

		return err
	}
	p.Header = header
	if len(input) < int(p.Header.Length) {
		return errors.New("Can not parse delete payload - input too short")
	}
	p.ProtocolID = input[0]
	p.SPISize = input[1]
	p.NumberOfSPIs = binary.BigEndian.Uint16(input[2:4])
	p.SPIs = input[4:p.Header.Length]
	return nil
}
func (p *DeletePayload) GetLength() uint16 {
	return p.Header.Length
}
func (p *DeletePayload) GetType() byte {
	return IKEConst.D
}
func (p *DeletePayload) GetNextPayload() byte {
	return p.Header.NextPayload
}
func (p *DeletePayload) SetNextPayload(payloadValue byte) {
	p.Header.NextPayload = payloadValue
}
