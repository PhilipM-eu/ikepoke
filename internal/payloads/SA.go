package payloads

import (
	"encoding/binary"
	"errors"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type SA struct {
	EncryptionAlgos       []uint16
	KeyLengths            []uint16
	PRFAlgos              []uint16
	IntegrityAlgos        []uint16
	DHGroups              []uint16
	ESNs                  []uint16
	AuthenticationMethods []uint16
	LifeTypes             []uint16
	LifeDurations         [][]byte
}

func (sa *SA) GetFirstAlgosIKEv2() (uint16, uint16, uint16, uint16, uint16) {
	var enc, keyLength, prf, integ, dhgroup uint16

	if len(sa.EncryptionAlgos) > 0 {
		enc = sa.EncryptionAlgos[0]
	}

	if len(sa.KeyLengths) > 0 {
		keyLength = sa.KeyLengths[0]
	}
	if len(sa.PRFAlgos) > 0 {
		prf = sa.PRFAlgos[0]
	}
	if len(sa.IntegrityAlgos) > 0 {
		integ = sa.IntegrityAlgos[0]
	}
	if len(sa.DHGroups) > 0 {
		dhgroup = sa.DHGroups[0]
	}
	return enc, keyLength, prf, integ, dhgroup

}
func (sa *SA) GetFirstAlgosIKEv1() (uint16, uint16, uint16, uint16, uint16, uint16, []byte) {
	var enc, keyLength, prf, dhGroup, authMethod, lifeType uint16
	var lifeDuration []byte
	if len(sa.EncryptionAlgos) > 0 {
		enc = sa.EncryptionAlgos[0]

	}
	if len(sa.KeyLengths) > 0 {
		keyLength = sa.KeyLengths[0]

	}

	if len(sa.PRFAlgos) > 0 {
		prf = sa.PRFAlgos[0]
	}

	if len(sa.DHGroups) > 0 {
		dhGroup = sa.DHGroups[0]
	}
	if len(sa.AuthenticationMethods) > 0 {
		authMethod = sa.AuthenticationMethods[0]

	}
	if len(sa.LifeTypes) > 0 {
		lifeType = sa.LifeTypes[0]

	}
	if len(sa.LifeDurations) > 0 {
		lifeDuration = sa.LifeDurations[0]

	}

	return enc, keyLength, prf, dhGroup, authMethod, lifeType, lifeDuration
}
func (sa *SA) AddAuthenticationMethod(authMethod uint16) {
	sa.AuthenticationMethods = append(sa.AuthenticationMethods, authMethod)

}
func (sa *SA) AddLifeDuration(duration []byte) {
	sa.LifeDurations = append(sa.LifeDurations, duration)

}
func (sa *SA) AddLifeType(lifeType uint16) {
	sa.LifeTypes = append(sa.LifeTypes, lifeType)

}
func (sa *SA) AddESN(esn uint16) {
	sa.ESNs = append(sa.ESNs, esn)

}
func (sa *SA) AddEncryption(encryptionAlgo, keyLength uint16) {
	sa.EncryptionAlgos = append(sa.EncryptionAlgos, encryptionAlgo)
	sa.KeyLengths = append(sa.KeyLengths, keyLength)
}
func (sa *SA) AddPRF(prf uint16) {
	sa.PRFAlgos = append(sa.PRFAlgos, prf)
}

func (sa *SA) AddIntegrity(intAlgo uint16) {
	sa.IntegrityAlgos = append(sa.IntegrityAlgos, intAlgo)
}

func (sa *SA) AddDHGroup(dhGroup uint16) {
	sa.DHGroups = append(sa.DHGroups, dhGroup)
}
func getBytesFromUint16(input uint16) []byte {
	result := make([]byte, 2)

	binary.BigEndian.PutUint16(result, input)
	return result
}
func (sa *SA) GetTransformsIKEv1(transformNumber byte) (error, *TransformPayload) {

	if len(sa.EncryptionAlgos) != len(sa.KeyLengths) {
		return errors.New("Encryption algorithms and key lengths do not match"), nil
	}
	transformID := byte(1) //KEY_IKE
	transform := NewTransformPayloadIKEv1(transformNumber, transformID)
	for i, encAlgo := range sa.EncryptionAlgos {
		transform.AddAttribute(IKEConst.ATTR_TV, IKEConst.TRANS_ENCR, getBytesFromUint16(encAlgo))
		keyLength := sa.KeyLengths[i]
		if keyLength != 0 {
			transform.AddAttribute(IKEConst.ATTR_TV, IKEConst.ATTR_KEYLENGTH, getBytesFromUint16(keyLength))
		}
	}
	//hash algo in ikev1
	for _, prf := range sa.PRFAlgos {
		transform.AddAttribute(IKEConst.ATTR_TV, IKEConst.TRANS_PRF, getBytesFromUint16(prf))
	}

	for _, dhGroup := range sa.DHGroups {
		transform.AddAttribute(IKEConst.ATTR_TV, IKEConst.TRANS_KE, getBytesFromUint16(dhGroup))
	}

	for _, authMethod := range sa.AuthenticationMethods {
		transform.AddAttribute(IKEConst.ATTR_TV, IKEConst.IKEv1_TRANS_AUTH, getBytesFromUint16(authMethod))
	}

	for _, lifeType := range sa.LifeTypes {

		transform.AddAttribute(IKEConst.ATTR_TV, IKEConst.IKEv1_TRANS_LIFETYPE, getBytesFromUint16(lifeType))
	}

	for _, lifeDuration := range sa.LifeDurations {
		transform.AddAttribute(IKEConst.ATTR_TLV, IKEConst.IKEv1_TRANS_LIFEDURATION, lifeDuration)
	}
	return nil, transform
}
func (sa *SA) GetTransformsIKEv2() (error, *[]TransformPayload) {
	if len(sa.EncryptionAlgos) != len(sa.KeyLengths) {
		return errors.New("Encryption algorithms and key lengths do not match"), nil
	}
	numberOfTransforms := len(sa.EncryptionAlgos) + len(sa.PRFAlgos) + len(sa.IntegrityAlgos) + len(sa.DHGroups)
	transforms := make([]TransformPayload, 0)
	for i, encAlgo := range sa.EncryptionAlgos {
		keyLength := sa.KeyLengths[i]
		transform := NewTransformPayloadIKEv2(IKEConst.TRANS_ENCR, encAlgo)
		// add attribute with key value pairs and key length type
		keyLengthBin := make([]byte, 2)
		binary.BigEndian.PutUint16(keyLengthBin, keyLength)
		transform.AddAttribute(IKEConst.ATTR_TV, IKEConst.ATTR_KEYLENGTH, keyLengthBin)
		if len(transforms) < numberOfTransforms-1 {
			transform.SetNextPayload(IKEConst.T)
		}
		transforms = append(transforms, *transform)
	}
	for _, prf := range sa.PRFAlgos {
		transform := NewTransformPayloadIKEv2(IKEConst.TRANS_PRF, prf)

		if len(transforms) < numberOfTransforms-1 {
			transform.SetNextPayload(IKEConst.T)
		}
		transforms = append(transforms, *transform)
	}

	for _, integAlgo := range sa.IntegrityAlgos {
		transform := NewTransformPayloadIKEv2(IKEConst.TRANS_INTEG, integAlgo)

		if len(transforms) < numberOfTransforms-1 {
			transform.SetNextPayload(IKEConst.T)
		}
		transforms = append(transforms, *transform)
	}

	for _, dhGroup := range sa.DHGroups {
		transform := NewTransformPayloadIKEv2(IKEConst.TRANS_KE, dhGroup)

		if len(transforms) < numberOfTransforms-1 {
			transform.SetNextPayload(IKEConst.T)
		}
		transforms = append(transforms, *transform)
	}
	for _, esn := range sa.ESNs {

		transform := NewTransformPayloadIKEv2(IKEConst.TRANS_ESN, esn)
		if len(transforms) < numberOfTransforms-1 {
			transform.SetNextPayload(IKEConst.T)
		}
		transforms = append(transforms, *transform)
	}

	return nil, &transforms
}
