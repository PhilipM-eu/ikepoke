package IKESession

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
	"github.com/PhilipM-eu/ikepoke/internal/IKEv1"
	"github.com/PhilipM-eu/ikepoke/internal/IKEv2"
	"github.com/PhilipM-eu/ikepoke/internal/encryption"
	"github.com/PhilipM-eu/ikepoke/internal/networking"
	"github.com/PhilipM-eu/ikepoke/internal/payloads"
)

type Session struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	LocalIP      string
	LocalPort    string
	RemoteIP     string
	RemotePort   string
	InitNonce    []byte
	RespNonce    []byte
	SessionKeys  SessionKeysIKEv2
	firstPacket  []byte
	Timeout      int
}
type SessionKeysIKEv2 struct {
	encAlgo      uint16
	encKeyLength int
	prfAlgo      uint16
	integAlgo    uint16
	KE           uint16
	KELength     int
	dhe          *encryption.DHExchange
	sharedDHKey  []byte
	skd          []byte
	skai         []byte
	skar         []byte
	skei         []byte
	sker         []byte
	skpi         []byte
	skpr         []byte
}

func (s *Session) PrintSessionKeys() {

	fmt.Printf("InitSPI: 0x%x\n", s.InitiatorSPI)
	fmt.Printf("RespSPI: 0x%x\n", s.ResponderSPI)
	fmt.Printf("Shared DH Key: 0x%x\n", s.SessionKeys.sharedDHKey)
	fmt.Printf("sk_d: 0x%x\n", s.SessionKeys.skd)
	fmt.Printf("sk_ai: 0x%x\n", s.SessionKeys.skai)
	fmt.Printf("sk_ar: 0x%x\n", s.SessionKeys.skar)
	fmt.Printf("sk_ei: 0x%x\n", s.SessionKeys.skei)
	fmt.Printf("sk_er: 0x%x\n", s.SessionKeys.sker)
	fmt.Printf("sk_pi: 0x%x\n", s.SessionKeys.skpi)
	fmt.Printf("sk_pr: 0x%x\n", s.SessionKeys.skpr)

}
func NewSession(localip, localport string, remoteip string, remoteport string, timeout int) Session {
	session := Session{}
	// each session should have a unique SPI. This does not have to cryptographically secure
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	session.InitiatorSPI = r.Uint64()
	session.ResponderSPI = 0
	session.LocalIP = localip
	session.LocalPort = localport
	session.RemoteIP = remoteip
	session.RemotePort = remoteport
	session.Timeout = timeout
	session.SessionKeys = SessionKeysIKEv2{}
	return session
}
func (s *SessionKeysIKEv2) setChosenAlgos(sas payloads.SA) error {

	var enc, encLength, prf, integ, dhgroup uint16
	enc, encLength, prf, integ, dhgroup = sas.GetFirstAlgosIKEv2()
	if s.KE != dhgroup {
		return errors.New("Host chose a different KE from the expected one")
	}
	s.encAlgo = enc
	s.encKeyLength = int(encLength)
	s.prfAlgo = prf
	s.integAlgo = integ

	return nil

}
func (s *Session) addKE(kexGroup uint16) {

	s.SessionKeys.KE = kexGroup
	s.SessionKeys.KELength = IKEConst.GetIKEv2KEXKeyLength(kexGroup)

}
func (s *Session) calculateKeys(dhPublicKey []byte) error {
	if s.SessionKeys.dhe == nil {
		return errors.New("Key exchange object not initialized")

	}
	sharedKey, err := s.SessionKeys.dhe.GenSharedSecret(dhPublicKey)
	if err != nil {
		log.Printf("Error during shared key generation %s\n", err)
		return err
	}
	s.SessionKeys.sharedDHKey = sharedKey
	//fmt.Println("Length of sharedKey", len(s.SessionKeys.sharedDHKey))
	//	fmt.Printf("SharedDH Key: 0x%x\n", s.SessionKeys.sharedDHKey)
	var integSize, prfSize int
	// use the integrity model
	integSize = 0
	// use the prf model -- USE SIZE in BYTES
	prfSize = 64
	keys := encryption.Keys{}
	initSPI := make([]byte, 8)
	respSPI := make([]byte, 8)
	binary.BigEndian.PutUint64(initSPI, s.InitiatorSPI)

	binary.BigEndian.PutUint64(respSPI, s.ResponderSPI)
	keys.Init(byte(s.SessionKeys.prfAlgo), s.InitNonce, s.RespNonce, initSPI, respSPI, s.SessionKeys.sharedDHKey)
	s.SessionKeys.skd, s.SessionKeys.skai, s.SessionKeys.skar, s.SessionKeys.skei, s.SessionKeys.sker, s.SessionKeys.skpi, s.SessionKeys.skpr = encryption.GetKeys((s.SessionKeys.encKeyLength/8)+4, integSize, prfSize, true, &keys)
	return nil
}
func (s *Session) GenDHKeys(dhGroup int, keyLength int) (error, []byte) {
	dhe := encryption.DHExchange{}
	err := dhe.Init(dhGroup, keyLength)
	if err != nil {
		return err, nil

	}
	s.SessionKeys.dhe = &dhe
	return nil, dhe.PubKey
}
func (s *Session) CalcAuthData(packet *IKEv2.IKEv2, psk []byte) {
	/// steps:
	// 1. get init payload data
	// 2. calc: prf(SK_pi, RestOfInitIDPayload)
	// 3. append bytes from INIT and noncedata from Responder
	// 4. append result from 2 to result from 3.
	// 5. calc prf(sharedSecret, "Key Pad for IKEv2"
	// 6. AUTHData = prf(result from 5., result from 4.)
	initPayloadData := packet.GetIdentificationDataSerialized()
	macedIDforI := encryption.PRF(byte(s.SessionKeys.prfAlgo), s.SessionKeys.skpi, initPayloadData)
	initSignedOctets := append(s.firstPacket, s.RespNonce...)
	initSignedOctets = append(initSignedOctets, macedIDforI...)
	//psk := []byte("1234")
	authData := encryption.CalcAuthFromSharedSecret(byte(s.SessionKeys.prfAlgo), psk, initSignedOctets)
	packet.AddAuthentication(2, authData)
}
func (s *Session) SendIKEv1InitMainMode(encAlgos map[uint16]uint16, prfAlgo, dhGroup, authMethod uint16) (IKEv1.IKEv1, error) {
	packet := *IKEv1.NewIKEv1Packet(s.InitiatorSPI, s.ResponderSPI, IKEConst.MAIN_MODE)

	sas := payloads.SA{}

	for encAlgo, keyLength := range encAlgos {
		sas.AddEncryption(encAlgo, keyLength)
	}
	sas.AddPRF(prfAlgo)
	sas.AddDHGroup(dhGroup)
	sas.AddAuthenticationMethod(authMethod)
	sas.AddLifeType(1)
	lifeDuration := make([]byte, 4)
	binary.BigEndian.PutUint32(lifeDuration, 86400)
	sas.AddLifeDuration(lifeDuration)

	saSlice := []*payloads.SA{&sas}
	packet.AddSAs(saSlice, 1, 1)

	packetBytes := packet.Serialize()

	s.firstPacket = packetBytes
	responseBytes, err := networking.SendIKEPacket(packetBytes, s.LocalIP, s.LocalPort, s.RemoteIP, s.RemotePort, s.Timeout)

	if err != nil {
		return IKEv1.IKEv1{}, err
	}
	response := IKEv1.IKEv1{}
	err = response.DeSerialize(responseBytes)
	if err != nil {

		return IKEv1.IKEv1{}, err
	}
	return response, nil
}
func (s *Session) SendIKEv1InitAggressiveMode(encAlgos map[uint16]uint16, prfAlgo, dhGroup, authMethod uint16) (IKEv1.IKEv1, error) {
	packet := *IKEv1.NewIKEv1Packet(s.InitiatorSPI, s.ResponderSPI, IKEConst.AGGRESSIVE_MODE)
	sas := payloads.SA{}

	for encAlgo, keyLength := range encAlgos {
		sas.AddEncryption(encAlgo, keyLength)
	}
	sas.AddPRF(prfAlgo)
	s.addKE(dhGroup)
	sas.AddDHGroup(dhGroup)
	sas.AddAuthenticationMethod(authMethod)
	sas.AddLifeType(1)
	lifeDuration := make([]byte, 4)
	binary.BigEndian.PutUint32(lifeDuration, 86400)
	sas.AddLifeDuration(lifeDuration)

	saSlice := []*payloads.SA{&sas}
	packet.AddSAs(saSlice, 1, 1)

	// kex payload
	err, pub := s.GenDHKeys(int(s.SessionKeys.KE), s.SessionKeys.KELength)
	if err != nil {

		return IKEv1.IKEv1{}, err
	}
	packet.AddKEX(s.SessionKeys.KE, pub)
	// nonce payload
	nonce := make([]byte, 20)
	rand.Read(nonce)
	packet.AddNonce(nonce)
	//id payload
	//packet.AddIdentification(3, 17, 0, []byte("test"))

	packet.AddIdentification(1, 17, 0, []byte{192, 168, 1, 100})
	// sending packet
	packetBytes := packet.Serialize()
	responseBytes, err := networking.SendIKEPacket(packetBytes, s.LocalIP, s.LocalPort, s.RemoteIP, s.RemotePort, s.Timeout)

	if err != nil {
		return IKEv1.IKEv1{}, err
	}
	response := IKEv1.IKEv1{}
	err = response.DeSerialize(responseBytes)
	if err != nil {

		return IKEv1.IKEv1{}, err
	}
	return response, nil
}
func (s *Session) ConnectToTargetIKEv2() bool {
	err, response := s.SendIKEv2SA(map[uint16]uint16{20: 256}, 7, 0, 21)
	if err != nil || response.GetFirstPayloadType() != IKEConst.SA {

		log.Println("Connection unsucessful")
		return false
	}
	s.ResponderSPI = response.Header.ResponderSPI
	s.RespNonce = response.GetNonceData()
	success, chosenSAs := response.GetSAs()
	if !success {
		return false
	}
	respPublicKey := response.GetKEXData()
	if respPublicKey == nil {
		return false
	}
	s.SessionKeys.setChosenAlgos(chosenSAs)
	err = s.calculateKeys(respPublicKey)
	if err != nil {
		log.Printf("Error calculating shared key: %s\n", err)
		return false
	}
	return true
}
func (s *Session) SendIKEv2SA(encAlgos map[uint16]uint16, prfAlgo, integAlgo, kexGroup uint16) (error, IKEv2.IKEv2) {
	packet := *IKEv2.NewIKEv2Packet(s.InitiatorSPI, s.ResponderSPI, IKEConst.IKE_SA_INIT)

	sas := payloads.SA{}

	for encAlgo, keyLength := range encAlgos {
		sas.AddEncryption(encAlgo, keyLength)
	}
	sas.AddPRF(prfAlgo)
	sas.AddIntegrity(integAlgo)
	s.addKE(kexGroup)
	sas.AddDHGroup(s.SessionKeys.KE)

	saSlice := []*payloads.SA{&sas}
	packet.AddSAs(saSlice, 1)

	err, pub := s.GenDHKeys(int(s.SessionKeys.KE), s.SessionKeys.KELength)
	if err != nil {
		log.Println(err)
		return err, IKEv2.IKEv2{}
	}
	//rand.Read(b)
	packet.AddKEX(s.SessionKeys.KE, pub)
	nonce := make([]byte, 32)
	rand.Read(nonce)
	packet.AddNonce(nonce)
	s.InitNonce = nonce
	packetBytes := packet.Serialize()
	s.firstPacket = packetBytes
	responseBytes, err := networking.SendIKEPacket(packetBytes, s.LocalIP, s.LocalPort, s.RemoteIP, s.RemotePort, s.Timeout)

	if err != nil {
		log.Println(err)
		return err, IKEv2.IKEv2{}
	}
	return parseResponse(responseBytes)
}
func parseResponse(input []byte) (error, IKEv2.IKEv2) {

	response := IKEv2.IKEv2{}
	err := response.DeSerialize(input)
	if err != nil {
		log.Println(err)
		return err, IKEv2.IKEv2{}
	}

	return err, response
}

type Auth struct {
	PSK         []byte
	IDType      byte
	ID          []byte
	TSiSourceIP []byte
	TSrStartIP  []byte
	TSrEndIP    []byte
}

func (s *Session) SendIKEv2AUTH(auth Auth) (error, IKEv2.IKEv2) {
	packet := *IKEv2.NewIKEv2Packet(s.InitiatorSPI, s.ResponderSPI, IKEConst.IKE_AUTH)
	packet.AddIdentification(auth.IDType, auth.ID, true)
	s.CalcAuthData(&packet, auth.PSK)

	// Security Associations for esp
	sas := payloads.SA{}
	sas.AddEncryption(20, 256)
	sas.AddESN(0)
	saSlice := []*payloads.SA{&sas}
	packet.AddSAs(saSlice, 3)

	// traffic selectors
	trafficSelectorsInit := []payloads.TrafficSelector{
		payloads.NewTrafficSelector(7, 0, 0, 65535, auth.TSiSourceIP, auth.TSiSourceIP),
	}
	trafficSelectorsResp := []payloads.TrafficSelector{
		payloads.NewTrafficSelector(7, 0, 0, 65535, auth.TSrStartIP, auth.TSrEndIP),
	}
	packet.AddTrafficSelectors(true, &trafficSelectorsInit)
	packet.AddTrafficSelectors(false, &trafficSelectorsResp)
	// encryption part
	err, response := s.SendEncryptedIKEv2Packet(&packet)
	if err != nil {
		log.Println(err)
		return err, IKEv2.IKEv2{}
	}
	return err, response
}
func (s *Session) SendEncryptedIKEv2Packet(packet *IKEv2.IKEv2) (error, IKEv2.IKEv2) {

	icvSize := 16
	ivSize := 8

	payloadData := packet.SerializePayload()
	payloadData = encryption.PadPlaintext(payloadData, 16)

	// reset payloads and add empty encrypted
	firstPayloadType := packet.Payload[0].GetType()
	packet.ResetPayload()
	packet.AddEncryptedEmpty(len(payloadData)+icvSize+ivSize, firstPayloadType)
	extraData := packet.Serialize()

	ciphertext, iv := encryption.EncryptPayload(byte(s.SessionKeys.encAlgo), payloadData, s.SessionKeys.skei, extraData)

	packet.AddDataToEncrypted(iv, ciphertext, nil)

	responseBytes, err := networking.SendIKEPacket(packet.Serialize(), s.LocalIP, s.LocalPort, s.RemoteIP, s.RemotePort, s.Timeout)
	if err != nil {
		log.Println(err)
		return err, IKEv2.IKEv2{}
	}
	return parseResponse(responseBytes)
}
func (s *Session) SendIKEv2Delete(encrypted bool) {

	packet := *IKEv2.NewIKEv2Packet(s.InitiatorSPI, s.ResponderSPI, IKEConst.INFORMATIONAL)
	packet.AddDelete(1, 0, 0, nil)
	if encrypted {

		s.SendEncryptedIKEv2Packet(&packet)
	} else {
		packet.Header.MessageID = 1
		networking.SendIKEPacket(packet.Serialize(), s.LocalIP, s.LocalPort, s.RemoteIP, s.RemotePort, s.Timeout)
	}
}
