package payloads

import (
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type VendorIDPayload struct {
	Header   PayloadHeader
	VendorID []byte
}

func (p *VendorIDPayload) Serialize() []byte {
	serialized := p.Header.Serialize()
	serialized = append(serialized, p.VendorID...)
	return serialized
}
func (p *VendorIDPayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {

		return err
	}
	p.Header = header

	if int(p.Header.Length) > len(input) {
		return errors.New("Cannot deserialize Vendor ID payload - input too short for supposed length")
	}
	p.VendorID = input[IKEConst.IKE_PAYLOAD_HEADER_LENGTH:p.Header.Length]
	return nil
}
func (p *VendorIDPayload) GetLength() uint16 {
	return p.Header.Length
}
func (p *VendorIDPayload) GetType() byte {
	return IKEConst.VID
}
func (p *VendorIDPayload) GetNextPayload() byte {
	return p.Header.NextPayload
}
func (p *VendorIDPayload) SetNextPayload(nextPayload byte) {
	p.Header.NextPayload = nextPayload
}
