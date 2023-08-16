package IKEv2

import (
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
	"github.com/PhilipM-eu/ikepoke/internal/IKEHeader"
	"github.com/PhilipM-eu/ikepoke/internal/payloads"
)

type IKEv2 struct {
	Header  IKEHeader.IKEHeader
	Payload []Payload
}

func NewIKEv2Packet(initSPI, respSPI uint64, exchangeType byte) *IKEv2 {
	packet := IKEv2{
		Header:  IKEHeader.IKEHeader{},
		Payload: make([]Payload, 0),
	}
	switch exchangeType {
	case IKEConst.IKE_SA_INIT:
		packet.Header.InitIKEv2SA(initSPI, respSPI)
	case IKEConst.IKE_AUTH:
		packet.Header.InitIKEv2Auth(initSPI, respSPI)
	case IKEConst.INFORMATIONAL:
		packet.Header.InitIKEv2Info(initSPI, respSPI)
	default:
		return nil
	}
	return &packet
}
func (p *IKEv2) ResetPayload() {
	p.Payload = make([]Payload, 0)
	p.Header.Length = IKEConst.IKE_HEADER_LENGTH
}

type Payload interface {
	Serialize() []byte
	DeSerialize([]byte) error
	GetLength() uint16
	GetType() byte
	GetNextPayload() byte
	SetNextPayload(byte)
}

func (p *IKEv2) GetFirstPayloadType() byte {
	if len(p.Payload) > 0 {
		return p.Payload[0].GetType()

	}
	return 0

}
func (p *IKEv2) GetFirstPayloadNextPayload() byte {
	if len(p.Payload) > 0 {
		return p.Payload[0].GetNextPayload()

	}
	return 0

}
func (p *IKEv2) Serialize() []byte {
	serialized := p.Header.Serialize()
	serialized = append(serialized, p.SerializePayload()...)
	return serialized
}
func (p *IKEv2) SerializePayload() []byte {
	serialized := make([]byte, 0)
	for _, payload := range p.Payload {
		serialized = append(serialized, payload.Serialize()...)
	}
	return serialized
}
func (p *IKEv2) DeSerialize(input []byte) error {
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
		case IKEConst.SA:
			payload = &payloads.SecurityAssociationPayload{IKEv1: false}
		case IKEConst.NI:
			payload = &payloads.NoncePayload{}
		case IKEConst.KE:
			payload = &payloads.KeyExchangePayload{IKEv1: false}
		case IKEConst.N:
			payload = &payloads.NotifyPayload{}
		case IKEConst.D:
			payload = &payloads.DeletePayload{}
		case IKEConst.IDi:
			payload = &payloads.IdentificationPayload{Initiator: true}
		case IKEConst.IDr:
			payload = &payloads.IdentificationPayload{Initiator: false}
		case IKEConst.AUTH:
			payload = &payloads.AuthenticationPayload{}
		case IKEConst.ENCAndAUTH:
			// TODO: Determine how to pass into deserialization which iv length and which checksum length was determined
			payload = &payloads.EncryptedPayload{}
		case IKEConst.TSi:
			payload = &payloads.TrafficSelectorPayload{Initiator: true}
		case IKEConst.TSr:
			payload = &payloads.TrafficSelectorPayload{Initiator: false}
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
func (p *IKEv2) GetKEXData() []byte {
	for _, payload := range p.Payload {
		if kexPayload, isKEX := payload.(*payloads.KeyExchangePayload); isKEX {
			return kexPayload.Data
		}
	}
	return nil
}
func (p *IKEv2) GetIdentificationDataSerialized() []byte {

	for _, payload := range p.Payload {
		if identificationPayload, isIdentification := payload.(*payloads.IdentificationPayload); isIdentification {
			return identificationPayload.SerializePayload()

		}
	}
	return nil
}
func (p *IKEv2) GetNonceData() []byte {

	for _, payload := range p.Payload {
		if noncePayload, isNonce := payload.(*payloads.NoncePayload); isNonce {
			return noncePayload.Data

		}
	}
	return nil

}
func (p *IKEv2) GetSAs() (bool, payloads.SA) {
	for _, payload := range p.Payload {
		if saPayload, isSA := payload.(*payloads.SecurityAssociationPayload); isSA {
			if len(saPayload.Proposals) > 0 {
				sas := saPayload.Proposals[0].GetTransformsFromProposal()
				return true, sas
			}
		}

	}
	return false, payloads.SA{}

}
func (p *IKEv2) setNextPayload(payloadType byte) {
	if len(p.Payload) == 0 {
		// payload slice is still empty -> set next payload in header
		p.Header.NextPayload = payloadType
	} else {
		// set the next payload on the last item in the payload slice
		p.Payload[len(p.Payload)-1].SetNextPayload(payloadType)
	}

}
func (p *IKEv2) AddDelete(protocolID, spiSize byte, numberOfSPIs uint16, spis []byte) {
	delPayload := payloads.NewDeletePayload(protocolID, spiSize, numberOfSPIs, spis)
	p.setNextPayload(IKEConst.D)
	p.Header.Length += uint32(delPayload.GetLength())
	p.Payload = append(p.Payload, delPayload)

}
func (p *IKEv2) AddSAs(securityAssociations []*payloads.SA, proposalType byte) error {
	err, saPayload := payloads.NewSAPayloadIKEv2(securityAssociations, proposalType)
	if err != nil {
		return err
	}
	p.setNextPayload(IKEConst.SA)
	p.Header.Length += uint32(saPayload.GetLength())
	p.Payload = append(p.Payload, saPayload)

	return nil
}
func (p *IKEv2) AddDataToEncrypted(iv, encData, integData []byte) error {
	if len(p.Payload) < 1 {
		return errors.New("No Encrypted payload available")
	}
	if encPayload, isENC := p.Payload[0].(*payloads.EncryptedPayload); isENC {
		encPayload.AddData(iv, encData, integData)
	} else {

		return errors.New("No encrypted Payload found")
	}
	return nil
}

// TODO   EncryptedAuthenticated
func (p *IKEv2) AddEncrypted(iv, encryptedData, checksum []byte, payloadTypeEncData byte) {
	encryptedPayload := payloads.NewEncryptedPayload(iv, encryptedData, checksum, payloadTypeEncData)
	p.setNextPayload(IKEConst.ENCAndAUTH)
	p.Header.Length += uint32(encryptedPayload.GetLength())
	p.Payload = append(p.Payload, encryptedPayload)

}
func (p *IKEv2) AddEncryptedEmpty(length int, payloadTypeEncData byte) {
	encryptedPayload := payloads.NewEncryptedPayloadEmpty(uint16(length), payloadTypeEncData)

	p.setNextPayload(IKEConst.ENCAndAUTH)
	p.Header.Length += uint32(encryptedPayload.GetLength())
	p.Payload = append(p.Payload, encryptedPayload)

}
func (p *IKEv2) AddTrafficSelectors(initiator bool, trafficSelectors *[]payloads.TrafficSelector) {
	tsPayload := payloads.NewTrafficSelectorPayload(initiator, trafficSelectors)
	nextPayload := IKEConst.TSi
	if !initiator {
		nextPayload = IKEConst.TSr
	}
	p.setNextPayload(byte(nextPayload))
	p.Header.Length += uint32(tsPayload.GetLength())
	p.Payload = append(p.Payload, tsPayload)

}
func (p *IKEv2) AddIdentification(idType byte, data []byte, initiator bool) {
	idPayload := payloads.NewIdentificationPayload(idType, data, initiator)
	nextPayload := IKEConst.IDi
	if !initiator {
		nextPayload = IKEConst.IDr
	}
	p.setNextPayload(byte(nextPayload))
	p.Header.Length += uint32(idPayload.GetLength())
	p.Payload = append(p.Payload, idPayload)

}
func (p *IKEv2) AddAuthentication(authMethod byte, data []byte) {
	authPayload := payloads.NewAuthenticationPayload(authMethod, data)
	p.setNextPayload(IKEConst.AUTH)
	p.Header.Length += uint32(authPayload.GetLength())
	p.Payload = append(p.Payload, authPayload)

}
func (p *IKEv2) AddNotify(protocolID byte, messageType uint16, spiData, notificationData []byte) {
	notifyPayload := payloads.NewNotifyPayload(protocolID, messageType, spiData, notificationData)
	p.setNextPayload(IKEConst.N)
	p.Header.Length += uint32(notifyPayload.GetLength())
	p.Payload = append(p.Payload, notifyPayload)

}
func (p *IKEv2) AddKEX(dhgroup uint16, data []byte) {
	kexPayload := payloads.NewKeyExchangePayload(dhgroup, data, false)
	p.setNextPayload(IKEConst.KE)

	p.Header.Length += uint32(kexPayload.GetLength())
	p.Payload = append(p.Payload, kexPayload)

}
func (p *IKEv2) AddNonce(data []byte) {
	noncePayload := payloads.NewNoncePayload(data, false)
	p.setNextPayload(IKEConst.NI)
	p.Header.Length += uint32(noncePayload.GetLength())
	p.Payload = append(p.Payload, noncePayload)
}
