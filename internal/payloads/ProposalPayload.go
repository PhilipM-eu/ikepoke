package payloads

import (
	"encoding/binary"
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type ProposalPayload struct {
	Header             PayloadHeader
	IKEv1              bool
	ProposalNumber     byte
	ProtocolID         byte
	SPISize            byte
	ProposalTransforms byte
	SPI                []byte
	Transforms         []TransformPayload
}

func (p *ProposalPayload) GetTransformsFromProposal() SA {
	var sa SA
	if p.IKEv1 {
		sa = p.getIKEv1Transforms()
	} else {
		sa = p.getIKEv2Transforms()
	}
	return sa
}
func (p *ProposalPayload) getIKEv2Transforms() SA {

	sa := SA{}
	for _, transform := range p.Transforms {
		switch transform.TransformType {
		case IKEConst.TRANS_ENCR:
			keyLength := uint16(0)
			if len(transform.Attributes) > 0 {
				keyLength = binary.BigEndian.Uint16(transform.Attributes[0].Value)
			}
			sa.AddEncryption(transform.TransformID, keyLength)
		case IKEConst.TRANS_PRF:
			sa.AddPRF(transform.TransformID)
		case IKEConst.TRANS_INTEG:
			sa.AddIntegrity(transform.TransformID)
		case IKEConst.TRANS_KE:
			sa.AddDHGroup(transform.TransformID)
		default:

		}

	}
	return sa
}
func (p *ProposalPayload) getIKEv1Transforms() SA {
	sa := SA{}
	if len(p.Transforms) <= 0 {
		return sa
	}
	for i, attribute := range p.Transforms[0].Attributes {
		switch attribute.Type {

		case IKEConst.TRANS_ENCR:
			enc := binary.BigEndian.Uint16(attribute.Value)
			keyLength := uint16(0)
			if i+1 < len(p.Transforms[0].Attributes) && p.Transforms[0].Attributes[i+1].Type == IKEConst.ATTR_KEYLENGTH {

				keyLength = binary.BigEndian.Uint16(p.Transforms[0].Attributes[i+1].Value)
			}

			sa.AddEncryption(enc, keyLength)

		case IKEConst.ATTR_KEYLENGTH:
		case IKEConst.TRANS_PRF:
			prf := binary.BigEndian.Uint16(attribute.Value)
			sa.AddPRF(prf)
		case IKEConst.TRANS_KE:
			kex := binary.BigEndian.Uint16(attribute.Value)
			sa.AddDHGroup(kex)
		case IKEConst.IKEv1_TRANS_AUTH:
			auth := binary.BigEndian.Uint16(attribute.Value)
			sa.AddAuthenticationMethod(auth)
		case IKEConst.IKEv1_TRANS_LIFETYPE:
			lifeType := binary.BigEndian.Uint16(attribute.Value)
			sa.AddLifeType(lifeType)
		case IKEConst.IKEv1_TRANS_LIFEDURATION:
			sa.AddLifeDuration(attribute.Value)
		default:

		}

	}
	return sa

}
func NewProposalPayload(proposalNumber, protoID byte, spi []byte, transforms *[]TransformPayload) *ProposalPayload {
	proposal := ProposalPayload{
		Header:             NewPayloadHeader(4 + uint16(len(spi))),
		ProposalNumber:     proposalNumber,
		ProtocolID:         protoID,
		SPISize:            byte(len(spi)),
		ProposalTransforms: byte(len(*transforms)),
		SPI:                spi,
		Transforms:         *transforms,
	}
	proposal.CalcLength()
	return &proposal
}
func (p *ProposalPayload) Serialize() []byte {
	serialized := p.Header.Serialize()
	propSerialized := make([]byte, 4)
	propSerialized[0] = p.ProposalNumber
	propSerialized[1] = p.ProtocolID
	propSerialized[2] = p.SPISize
	propSerialized[3] = p.ProposalTransforms
	propSerialized = append(propSerialized, p.SPI...)
	for _, transform := range p.Transforms {
		propSerialized = append(propSerialized, transform.Serialize()...)
	}

	serialized = append(serialized, propSerialized...)
	return serialized
}
func (p *ProposalPayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	p.Header = header
	if len(input) < int(p.Header.Length) || len(input) < 8 {
		return errors.New("Input too short for supposed proposal length")
	}
	p.ProposalNumber = input[4]
	p.ProtocolID = input[5]
	p.SPISize = input[6]
	p.ProposalTransforms = input[7]
	if p.SPISize > 0 {
		p.SPI = input[8 : 8+p.SPISize]
	}
	currentPosition := 8 + int(p.SPISize)
	nextPayload := byte(IKEConst.T)
	for currentPosition < int(p.Header.Length) && nextPayload == IKEConst.T && len(p.Transforms) < int(p.ProposalTransforms) {
		transform := TransformPayload{IKEv1: p.IKEv1}
		err := transform.DeSerialize(input[currentPosition:p.Header.Length])
		if err != nil {
			return err
		}
		currentPosition += int(transform.Header.Length)
		nextPayload = transform.GetNextPayload()
		p.Transforms = append(p.Transforms, transform)
	}

	return nil
}
func (p *ProposalPayload) CalcLength() {
	length := uint16(IKEConst.IKE_PAYLOAD_HEADER_LENGTH + 4 + p.SPISize)
	for _, transform := range p.Transforms {
		length += transform.GetLength()
	}
	p.Header.Length = length

}
func (p *ProposalPayload) GetLength() uint16 {
	return p.Header.Length
}
func (p *ProposalPayload) GetType() byte {
	return IKEConst.P

}
func (p *ProposalPayload) GetNextPayload() byte {
	return p.Header.NextPayload

}
func (p *ProposalPayload) SetNextPayload(payloadType byte) {
	p.Header.NextPayload = payloadType
}
