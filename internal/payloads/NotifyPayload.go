package payloads

import (
	"encoding/binary"
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type NotifyPayload struct {
	Header                 PayloadHeader
	DomainOfInterpretation uint32
	ProtocolID             byte
	SPISize                byte
	NotifyMessageType      uint16
	SPIData                []byte
	NotificationData       []byte
	IKEv1                  bool
}

func NewNotifyPayload(protocolID byte, messageType uint16, spiData, notificationData []byte) *NotifyPayload {
	notify := NotifyPayload{
		Header:            NewPayloadHeader(uint16(4 + len(spiData) + len(notificationData))),
		ProtocolID:        protocolID,
		SPISize:           byte(len(spiData)),
		NotifyMessageType: messageType,
		SPIData:           spiData,
		NotificationData:  notificationData,
	}

	return &notify
}
func (n *NotifyPayload) Serialize() []byte {
	serialized := n.Header.Serialize()
	notifySerialized := make([]byte, 4)
	notifySerialized[0] = n.ProtocolID
	notifySerialized[1] = n.SPISize
	binary.BigEndian.PutUint16(notifySerialized[2:4], n.NotifyMessageType)
	if n.IKEv1 {
		domainSerialized := make([]byte, 4)
		binary.BigEndian.PutUint32(domainSerialized, n.DomainOfInterpretation)
		notifySerialized = append(domainSerialized, notifySerialized...)
	}
	serialized = append(serialized, notifySerialized...)
	serialized = append(serialized, n.SPIData...)
	serialized = append(serialized, n.NotificationData...)
	return serialized
}
func (n *NotifyPayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	n.Header = header
	if len(input) < int(n.Header.Length) || len(input) < int(IKEConst.IKE_PAYLOAD_HEADER_LENGTH)+4 {
		return errors.New("Input too short to deserialize notify payload ")
	}
	currentPosition := IKEConst.IKE_PAYLOAD_HEADER_LENGTH
	if n.IKEv1 {
		n.DomainOfInterpretation = binary.BigEndian.Uint32(input[currentPosition : currentPosition+4])
		currentPosition += 4

	}
	n.ProtocolID = input[currentPosition]
	n.SPISize = input[currentPosition+1]
	n.NotifyMessageType = binary.BigEndian.Uint16(input[currentPosition+2 : currentPosition+4])
	if n.SPISize > 0 {
		n.SPIData = input[currentPosition+4 : currentPosition+4+int(n.SPISize)]
	}
	n.NotificationData = input[currentPosition+4+int(n.SPISize) : n.Header.Length]
	return nil
}
func (n *NotifyPayload) GetLength() uint16 {
	return n.Header.Length
}
func (n *NotifyPayload) GetType() byte {
	if n.IKEv1 {
		return IKEConst.IKEv1_N
	}
	return IKEConst.N
}
func (n *NotifyPayload) GetNextPayload() byte {
	return n.Header.NextPayload
}
func (n *NotifyPayload) SetNextPayload(payloadType byte) {
	n.Header.NextPayload = payloadType
}
