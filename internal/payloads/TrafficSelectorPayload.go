package payloads

import (
	"encoding/binary"
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type TrafficSelectorPayload struct {
	Header     PayloadHeader
	NumberOfTS byte
	// reserved 3 bytes in size
	Reserved         []byte
	TrafficSelectors []TrafficSelector
	Initiator        bool
}
type TrafficSelector struct {
	TSType       byte
	IPProtocolID byte // specifies transport protocol i.e. TCP,UDP or ICMP -> 0 means all are supported
	Length       uint16
	StartPort    uint16
	EndPort      uint16
	StartAddress []byte // length of the addresses depends on the TSType i.e. IPv4 or v6 (four octet length or 16 octett length
	EndAddress   []byte
}

func NewTrafficSelectorPayload(initiator bool, trafficSelectors *[]TrafficSelector) *TrafficSelectorPayload {
	ts := TrafficSelectorPayload{
		NumberOfTS:       byte(len(*trafficSelectors)),
		Reserved:         make([]byte, 3),
		TrafficSelectors: *trafficSelectors,
		Initiator:        initiator,
	}
	length := uint16(4)
	for _, t := range ts.TrafficSelectors {
		length += t.Length
	}
	ts.Header = NewPayloadHeader(length)

	return &ts
}
func NewTrafficSelector(tsType, ipProtocolID byte, startPort, endPort uint16, startAddress, endAddress []byte) TrafficSelector {
	if !(len(startAddress) == 4 || len(startAddress) == 16) || len(startAddress) != len(endAddress) {
		return TrafficSelector{}
	}
	t := TrafficSelector{
		TSType:       tsType,
		IPProtocolID: ipProtocolID,
		Length:       8 + uint16(len(startAddress)+len(endAddress)),
		StartPort:    startPort,
		EndPort:      endPort,
		StartAddress: startAddress,
		EndAddress:   endAddress,
	}
	return t
}
func (ts *TrafficSelectorPayload) Serialize() []byte {
	serialized := ts.Header.Serialize()
	serialized = append(serialized, ts.NumberOfTS)
	serialized = append(serialized, ts.Reserved...)
	for _, trafficSelector := range ts.TrafficSelectors {
		serialized = append(serialized, trafficSelector.Serialize()...)
	}

	return serialized
}
func (t *TrafficSelector) Serialize() []byte {
	serialized := make([]byte, 8)
	serialized[0] = t.TSType
	serialized[1] = t.IPProtocolID
	binary.BigEndian.PutUint16(serialized[2:4], t.Length)

	binary.BigEndian.PutUint16(serialized[4:6], t.StartPort)
	binary.BigEndian.PutUint16(serialized[6:8], t.EndPort)
	serialized = append(serialized, t.StartAddress...)
	serialized = append(serialized, t.EndAddress...)
	return serialized
}
func (t *TrafficSelector) DeSerialize(input []byte) error {
	if len(input) < 16 {
		return errors.New("Unable to deserialize traffic selector - input too short")
	}

	t.TSType = input[0]
	t.IPProtocolID = input[1]
	t.Length = binary.BigEndian.Uint16(input[2:4])
	t.StartPort = binary.BigEndian.Uint16(input[4:6])
	t.EndPort = binary.BigEndian.Uint16(input[6:8])
	//ipv4
	if t.TSType == 7 {
		t.StartAddress = input[8:12]
		t.EndAddress = input[12:16]
		//ipv6
	} else if t.TSType == 8 {
		t.StartAddress = input[8:24]
		t.EndAddress = input[24:40]
	} else {
		return errors.New("Unable to deserialize traffic selector - unknown tstype")
	}
	return nil
}
func (ts *TrafficSelectorPayload) DeSerialize(input []byte) error {
	header := PayloadHeader{}
	err := header.DeSerialize(input)
	if err != nil {
		return err
	}
	ts.Header = header
	if len(input) < int(ts.Header.Length) {
		return errors.New("Cannot deserialize traffic selector - Input too short for supposed Length")
	}
	ts.NumberOfTS = input[4]

	ts.Reserved = input[5:8]
	currentPosition := 8
	for i := 0; i < int(ts.NumberOfTS) && currentPosition < len(input); i++ {
		t := TrafficSelector{}
		err = t.DeSerialize(input[currentPosition:])
		if err != nil {
			return err
		}
		currentPosition += int(t.Length)
		ts.TrafficSelectors = append(ts.TrafficSelectors, t)
	}
	return nil
}
func (ts *TrafficSelectorPayload) GetLength() uint16 {
	return ts.Header.Length
}
func (ts *TrafficSelectorPayload) GetType() byte {
	if ts.Initiator {
		return IKEConst.TSi
	} else {
		return IKEConst.TSr
	}
}
func (ts *TrafficSelectorPayload) GetNextPayload() byte {
	return ts.Header.NextPayload
}
func (ts *TrafficSelectorPayload) SetNextPayload(payloadType byte) {
	ts.Header.NextPayload = payloadType
}
