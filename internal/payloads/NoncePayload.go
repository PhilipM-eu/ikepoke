package payloads

import (
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type NoncePayload struct {
	Header PayloadHeader
	Data   []byte
	IKEv1  bool
}

func NewNoncePayload(nonceData []byte, ikev1 bool) *NoncePayload {
	payload := NoncePayload{
		Header: NewPayloadHeader(uint16(len(nonceData))),
		Data:   nonceData,
		IKEv1:  ikev1,
	}
	return &payload
}
func (n *NoncePayload) Serialize() []byte {
	serialized := n.Header.Serialize()
	serialized = append(serialized, n.Data...)
	return serialized
}

func (n *NoncePayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	n.Header = header

	if len(input) < int(n.Header.Length) {
		return errors.New("Input too short to deserialize nonce payload")
	}
	n.Data = input[4:n.Header.Length]
	return nil
}
func (n *NoncePayload) GetLength() uint16 {
	return n.Header.Length

}
func (n *NoncePayload) GetType() byte {
	if n.IKEv1 {
		return IKEConst.IKEv1_NONCE
	}
	return IKEConst.NI

}
func (n *NoncePayload) SetNextPayload(payloadType byte) {
	n.Header.NextPayload = payloadType
}
func (n *NoncePayload) GetNextPayload() byte {
	return n.Header.NextPayload

}
