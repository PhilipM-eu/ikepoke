package transforms

import (
	"errors"
	"log"
	"strconv"
	"strings"
)

type SingleSAIKEv2 struct {
	EncAlgo   uint16
	KeyLength uint16
	PRFAlgo   uint16
	IntegAlgo uint16
	DhGroup   uint16
}

func ParseTargetTransformIKEv2(rawTransform string) (SingleSAIKEv2, error) {
	result := SingleSAIKEv2{}
	algos := strings.Split(rawTransform, ",")
	if len(algos) != 4 {
		return result, errors.New("Input transform malformed")
	}
	encAndLength := strings.Split(algos[0], "/")
	switch len(encAndLength) {
	case 2:

		keyLength, err := strconv.ParseInt(encAndLength[1], 10, 16)
		if err != nil {
			return result, err
		}
		result.KeyLength = uint16(keyLength)
		fallthrough
	case 1:
		enc, err := strconv.ParseInt(encAndLength[0], 10, 16)
		if err != nil {
			return result, err
		}
		result.EncAlgo = uint16(enc)
	default:
		log.Println("Error parsing transform - Enc Algorithm")
		return result, errors.New("Input transform malformed- Cannot parse encryption algorithm")
	}

	prfAlgo, err := strconv.ParseInt(algos[1], 10, 16)
	if err != nil {
		log.Println("Error parsing transform - PRF Algorithm")
		return result, err
	}
	result.PRFAlgo = uint16(prfAlgo)
	integAlgo, err := strconv.ParseInt(algos[2], 10, 16)
	if err != nil {
		log.Println("Error parsing transform - Integrity Algorithm")
		return result, err
	}
	result.IntegAlgo = uint16(integAlgo)
	dhGroup, err := strconv.ParseInt(algos[3], 10, 16)
	if err != nil {
		log.Println("Error parsing transform -  Dh Group")
		return result, err
	}
	result.DhGroup = uint16(dhGroup)
	return result, nil

}
func (s *SingleSAIKEv2) GetType() int {
	return 1
}
func (s *SingleSAIKEv2) GetCopy() *SingleSAIKEv2 {
	return &SingleSAIKEv2{EncAlgo: s.EncAlgo, KeyLength: s.KeyLength, PRFAlgo: s.PRFAlgo, IntegAlgo: s.IntegAlgo, DhGroup: s.DhGroup}
}

type SingleSAIKEv1 struct {
	EncAlgo        uint16
	KeyLength      uint16
	HashAlgo       uint16
	DhGroup        uint16
	AuthMethod     uint16
	AggressiveMode bool
}

func ParseTargetTransformIKEv1(rawTransform string, aggressiveMode bool) (SingleSAIKEv1, error) {
	result := SingleSAIKEv1{AggressiveMode: aggressiveMode}
	algos := strings.Split(rawTransform, ",")
	if len(algos) != 4 {
		return result, errors.New("Input transform malformed")
	}
	encAndLength := strings.Split(algos[0], "/")
	switch len(encAndLength) {
	case 2:

		keyLength, err := strconv.ParseInt(encAndLength[1], 10, 16)
		if err != nil {
			return result, err
		}
		result.KeyLength = uint16(keyLength)
		fallthrough
	case 1:
		enc, err := strconv.ParseInt(encAndLength[0], 10, 16)
		if err != nil {
			return result, err
		}
		result.EncAlgo = uint16(enc)
	default:
		log.Println("Error parsing transform - Enc Algorithm")
		return result, errors.New("Input transform malformed- Cannot parse encryption algorithm")
	}

	hashAlgo, err := strconv.ParseInt(algos[1], 10, 16)
	if err != nil {
		log.Println("Error parsing transform - Hash Algorithm")
		return result, err
	}
	result.HashAlgo = uint16(hashAlgo)

	authMethod, err := strconv.ParseInt(algos[2], 10, 16)
	if err != nil {
		log.Println("Error parsing transform - Auth method")
		return result, err
	}
	result.AuthMethod = uint16(authMethod)
	dhGroup, err := strconv.ParseInt(algos[3], 10, 16)
	if err != nil {
		log.Println("Error parsing transform -  Dh Group")
		return result, err
	}
	result.DhGroup = uint16(dhGroup)
	return result, nil

}
func (s *SingleSAIKEv1) GetCopy() *SingleSAIKEv1 {
	return &SingleSAIKEv1{EncAlgo: s.EncAlgo, KeyLength: s.KeyLength, HashAlgo: s.HashAlgo, DhGroup: s.DhGroup, AuthMethod: s.AuthMethod, AggressiveMode: s.AggressiveMode}
}
func (s *SingleSAIKEv1) GetType() int {
	return 0
}
