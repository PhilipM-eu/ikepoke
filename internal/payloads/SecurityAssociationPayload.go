package payloads

import (
	"encoding/binary"
	"errors"
	"math/rand"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type SecurityAssociationPayload struct {
	Header                 PayloadHeader
	IKEv1                  bool
	DomainOfInterpretation uint32
	Situation              uint32
	Proposals              []ProposalPayload
}

func NewSAPayloadIKEv1(securityAssociations []*SA, domainOfInterpretation, situation uint32) (error, *SecurityAssociationPayload) {
	proposals := make([]ProposalPayload, 0)

	length := uint16(8)
	for i, sas := range securityAssociations {
		err, transforms := sas.GetTransformsIKEv1(byte(i + 1))
		if err != nil {
			return err, nil
		}
		proposal := *NewProposalPayload(byte(i+1), IKEConst.PROP_ISAKMP, nil, &[]TransformPayload{*transforms})
		length += proposal.GetLength()
		if i < len(securityAssociations)-1 {
			proposal.SetNextPayload(IKEConst.P)

		}
		proposals = append(proposals, proposal)
	}
	header := NewPayloadHeader(length)
	saPayload := SecurityAssociationPayload{
		Header:                 header,
		DomainOfInterpretation: domainOfInterpretation,
		Situation:              situation,
		Proposals:              proposals,
		IKEv1:                  true,
	}
	return nil, &saPayload
}
func NewSAPayloadIKEv2(securityAssociations []*SA, proposalType byte) (error, *SecurityAssociationPayload) {

	proposals := make([]ProposalPayload, 0)
	length := uint16(0)
	//TODO: add spi as slice to new proposal
	var spi []byte = nil
	if proposalType == 3 {

		spi = make([]byte, 4)
		binary.BigEndian.PutUint32(spi, rand.Uint32())
	}

	for i, sas := range securityAssociations {
		err, transforms := sas.GetTransformsIKEv2()
		if err != nil {
			return err, nil
		}
		proposal := *NewProposalPayload(byte(i+1), proposalType, spi, transforms)
		length += proposal.GetLength()
		if i < len(securityAssociations)-1 {
			proposal.SetNextPayload(IKEConst.P)

		}
		proposals = append(proposals, proposal)
	}
	header := NewPayloadHeader(length)
	saPayload := SecurityAssociationPayload{
		Header:    header,
		Proposals: proposals,
		IKEv1:     false,
	}
	return nil, &saPayload
}

func (sa *SecurityAssociationPayload) Serialize() []byte {
	serialized := sa.Header.Serialize()
	if sa.IKEv1 {
		ikev1Serialized := make([]byte, 8)
		binary.BigEndian.PutUint32(ikev1Serialized[0:4], sa.DomainOfInterpretation)
		binary.BigEndian.PutUint32(ikev1Serialized[4:8], sa.Situation)
		serialized = append(serialized, ikev1Serialized...)

	}
	for _, proposal := range sa.Proposals {
		serialized = append(serialized, proposal.Serialize()...)
	}
	return serialized
}
func (sa *SecurityAssociationPayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	sa.Header = header
	currentPosition := IKEConst.IKE_PAYLOAD_HEADER_LENGTH
	if sa.IKEv1 {
		sa.DomainOfInterpretation = binary.BigEndian.Uint32(input[currentPosition : currentPosition+4])
		currentPosition += 4
		sa.Situation = binary.BigEndian.Uint32(input[currentPosition : currentPosition+4])
		currentPosition += 4

	}

	nextPayload := byte(IKEConst.P)

	for currentPosition < int(sa.Header.Length) && nextPayload != 0 {
		switch nextPayload {
		case IKEConst.P:
			proposal := ProposalPayload{IKEv1: sa.IKEv1}
			err = proposal.DeSerialize(input[currentPosition:sa.Header.Length])
			if err != nil {
				return err
			}
			currentPosition += int(proposal.Header.Length)
			nextPayload = proposal.GetNextPayload()
			sa.Proposals = append(sa.Proposals, proposal)
		default:
			return errors.New("Cannot parse SA payload - supposed length longer than input")
		}
	}

	return nil
}
func (sa *SecurityAssociationPayload) GetLength() uint16 {
	return sa.Header.Length
}
func (sa *SecurityAssociationPayload) GetType() byte {
	return IKEConst.SA
}
func (sa *SecurityAssociationPayload) GetNextPayload() byte {
	return sa.Header.NextPayload
}
func (sa *SecurityAssociationPayload) SetNextPayload(payloadType byte) {
	sa.Header.NextPayload = payloadType
}
