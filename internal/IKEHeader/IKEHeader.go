package IKEHeader

import (
	"encoding/binary"
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type IKEHeader struct {

	// Choose a uniqe SPI for each connection. These identify the actual connections and not the Src IP+port
	InitiatorSPI uint64
	// Responder SPI can be set to 0 in the first packet. Afterwards use the SPI from the recieved response https://www.rfc-editor.org/rfc/rfc7296.html#page-32
	ResponderSPI uint64
	NextPayload  byte
	Version      byte
	// possible types https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
	// 34 == SA INIT, 35 == IKE_AUTH,
	ExchangeType byte
	// Flags are XXRVIXXX, X must be cleared in good implementations, R indicates that this message is a response to a message with the same messageID, V indicates the implemetation can speak a higher major version (should be cleared and ignored with IKEv2), I indicates who the original initatior for a SA is
	Flags     byte
	MessageID uint32
	Length    uint32
}

func (i *IKEHeader) Serialize() []byte {
	serialized := make([]byte, IKEConst.IKE_HEADER_LENGTH)
	if i.Length < IKEConst.IKE_HEADER_LENGTH {
		return serialized
	}
	binary.BigEndian.PutUint64(serialized[:8], i.InitiatorSPI)
	binary.BigEndian.PutUint64(serialized[8:16], i.ResponderSPI)
	serialized[16] = i.NextPayload
	serialized[17] = i.Version
	serialized[18] = i.ExchangeType
	serialized[19] = i.Flags
	binary.BigEndian.PutUint32(serialized[20:24], i.MessageID)
	binary.BigEndian.PutUint32(serialized[24:28], i.Length)
	return serialized
}
func (i *IKEHeader) DeSerialize(input []byte) error {
	if len(input) < IKEConst.IKE_HEADER_LENGTH {
		return errors.New("Input too short to deserialize IKE header.")
	}
	i.InitiatorSPI = binary.BigEndian.Uint64(input[:8])
	i.ResponderSPI = binary.BigEndian.Uint64(input[8:16])
	i.NextPayload = input[16]
	i.Version = input[17]
	i.ExchangeType = input[18]
	i.Flags = input[19]
	i.MessageID = binary.BigEndian.Uint32(input[20:24])
	i.Length = binary.BigEndian.Uint32(input[24:28])
	return nil
}
func (i *IKEHeader) InitIKEv1MainMode(initSPI, respSPI uint64) {
	i.init(initSPI, respSPI, IKEConst.IKEv1)
	i.ExchangeType = IKEConst.MAIN_MODE
	i.MessageID = 0
	i.Flags = 0x00
}

func (i *IKEHeader) InitIKEv1AgressiveMode(initSPI, respSPI uint64) {
	i.init(initSPI, respSPI, IKEConst.IKEv1)
	i.ExchangeType = IKEConst.AGGRESSIVE_MODE
	i.MessageID = 0
}
func (i *IKEHeader) InitIKEv2SA(initSPI, respSPI uint64) {

	i.init(initSPI, respSPI, IKEConst.IKEv2)
	i.ExchangeType = IKEConst.IKE_SA_INIT
	i.MessageID = 0
}
func (i *IKEHeader) InitIKEv2Auth(initSPI, respSPI uint64) {
	i.init(initSPI, respSPI, IKEConst.IKEv2)
	i.ExchangeType = IKEConst.IKE_AUTH
	i.MessageID = 1
}
func (i *IKEHeader) InitIKEv2Info(initSPI, respSPI uint64) {

	i.init(initSPI, respSPI, IKEConst.IKEv2)
	i.ExchangeType = IKEConst.INFORMATIONAL
	i.MessageID = 2

}
func (i *IKEHeader) init(initSPI, respSPI uint64, version byte) {
	i.InitiatorSPI = initSPI
	i.ResponderSPI = respSPI
	i.Version = version
	i.Flags = 0x08
	i.Length = IKEConst.IKE_HEADER_LENGTH

}
