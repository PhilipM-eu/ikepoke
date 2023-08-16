package IKEv1

import (
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
	"github.com/PhilipM-eu/ikepoke/internal/IKEHeader"

	"github.com/PhilipM-eu/ikepoke/internal/payloads"
)

type IKEv1 struct {
	Header  IKEHeader.IKEHeader
	Payload []Payload
}

func NewIKEv1Packet(initSPI, respSPI uint64, exchangeType byte) *IKEv1 {
	packet := IKEv1{
		Header:  IKEHeader.IKEHeader{},
		Payload: make([]Payload, 0),
	}
	switch exchangeType {
	case IKEConst.MAIN_MODE:
		packet.Header.InitIKEv1MainMode(initSPI, respSPI)
	case IKEConst.AGGRESSIVE_MODE:
		packet.Header.InitIKEv1AgressiveMode(initSPI, respSPI)
	default:
		return nil
	}
	return &packet
}

type Payload interface {
	Serialize() []byte
	DeSerialize([]byte) error
	GetLength() uint16
	GetType() byte
	GetNextPayload() byte
	SetNextPayload(byte)
}

func (p *IKEv1) GetNotifyType() (uint16, error) {

	for _, payload := range p.Payload {
		if notifyPayload, isNotify := payload.(*payloads.NotifyPayload); isNotify {
			return notifyPayload.NotifyMessageType, nil
		}
	}
	return 0, errors.New("No notification payload")

}
func (p *IKEv1) DeSerialize(input []byte) error {
	header := IKEHeader.IKEHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	p.Header = header

	if len(input) < int(p.Header.Length) {
		return errors.New("Cannot parse input - input length shorther than supposed IKE Packet length")
	}

	currentPosition := IKEConst.IKE_HEADER_LENGTH
	nextPayload := p.Header.NextPayload

	for currentPosition < int(p.Header.Length) && nextPayload != 0 {
		if currentPosition >= len(input) {
			return errors.New("Could not parse whole input. Length of supposed packet and received input do not match")
		}
		var payload Payload
		switch nextPayload {
		case IKEConst.IKEv1_SA:
			payload = &payloads.SecurityAssociationPayload{IKEv1: true}
		case IKEConst.IKEv1_KE:
			payload = &payloads.KeyExchangePayload{IKEv1: true}
		case IKEConst.IKEv1_NONCE:

			payload = &payloads.NoncePayload{IKEv1: true}
		case IKEConst.H:
			payload = &payloads.HashPayload{}
		case IKEConst.ID:
			payload = &payloads.IdentificationPayloadIKEv1{}
		case IKEConst.VID:
			payload = &payloads.VendorIDPayload{}
		case IKEConst.IKEv1_N:
			payload = &payloads.NotifyPayload{IKEv1: true}
		default:
			return errors.New("Cannot parse input - unknown payload type")
		}

		err = payload.DeSerialize(input[currentPosition:])
		if err != nil {
			return err
		}
		nextPayload = payload.GetNextPayload()
		currentPosition += int(payload.GetLength())
		p.Payload = append(p.Payload, payload)
	}
	return nil
}
func (p *IKEv1) Serialize() []byte {
	serialized := p.Header.Serialize()
	serialized = append(serialized, p.SerializePayload()...)
	return serialized
}
func (p *IKEv1) SerializePayload() []byte {
	serialized := make([]byte, 0)
	for _, payload := range p.Payload {
		serialized = append(serialized, payload.Serialize()...)
	}
	return serialized
}

func (p *IKEv1) setNextPayload(payloadType byte) {
	if len(p.Payload) == 0 {
		// payload slice is still empty -> set next payload in header
		p.Header.NextPayload = payloadType
	} else {
		// set the next payload on the last item in the payload slice
		p.Payload[len(p.Payload)-1].SetNextPayload(payloadType)
	}

}
func (p *IKEv1) AddIdentification(idType, protocolID byte, port uint16, data []byte) {
	// idType, protocolID byte, port uint16, data []byte
	idPayload := payloads.NewIdentificationPayloadIKEv1(idType, protocolID, port, data)

	p.setNextPayload(IKEConst.ID)
	p.Header.Length += uint32(idPayload.GetLength())
	p.Payload = append(p.Payload, idPayload)
}

func (p *IKEv1) AddHash(data []byte) {
	hashPayload := payloads.NewHashPayload(data)
	p.setNextPayload(IKEConst.H)
	p.Header.Length += uint32(hashPayload.GetLength())
	p.Payload = append(p.Payload, hashPayload)
}
func (p *IKEv1) AddNonce(data []byte) {
	noncePayload := payloads.NewNoncePayload(data, true)
	p.setNextPayload(IKEConst.IKEv1_NONCE)
	p.Header.Length += uint32(noncePayload.GetLength())
	p.Payload = append(p.Payload, noncePayload)
}
func (p *IKEv1) AddKEX(dhgroup uint16, data []byte) {
	kexPayload := payloads.NewKeyExchangePayload(dhgroup, data, true)

	p.setNextPayload(IKEConst.IKEv1_KE)

	p.Header.Length += uint32(kexPayload.GetLength())
	p.Payload = append(p.Payload, kexPayload)

}
func (p *IKEv1) GetSAs() (bool, payloads.SA) {

	success := false
	for _, payload := range p.Payload {
		if saPayload, isSA := payload.(*payloads.SecurityAssociationPayload); isSA {
			if len(saPayload.Proposals) > 0 {
				sas := saPayload.Proposals[0].GetTransformsFromProposal()
				return !success, sas
			}
		}
	}
	return success, payloads.SA{}

}
func (p *IKEv1) AddSAs(securityAssociations []*payloads.SA, domainOfInterpretation, situation uint32) error {
	err, saPayload := payloads.NewSAPayloadIKEv1(securityAssociations, domainOfInterpretation, situation)
	if err != nil {
		return err
	}
	p.setNextPayload(IKEConst.IKEv1_SA)
	p.Header.Length += uint32(saPayload.GetLength())
	p.Payload = append(p.Payload, saPayload)

	return nil
}
