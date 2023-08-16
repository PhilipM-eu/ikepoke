package targets

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
)

type Target struct {
	IP             string
	Port           string
	CryptoIKEv1    TargetCryptoIKEv1
	CryptoIKEv2    TargetCryptoIKEv2
	IKEv1Supported bool
	IKEv2Supported bool
}

func ReadTargetfile(filepath string) ([]*Target, error) {
	targets := make([]*Target, 0)
	f, err := os.Open(filepath)
	if err != nil {
		log.Fatalf("Error reading targetfile: %s", err)
		return nil, err
	}
	// remember to close the file at the end of the program
	defer f.Close()
	//read the targets line by line
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {

		line := scanner.Text()
		err, target := GetTarget(line)
		if err != nil {
			log.Fatalf("Failure to parse targetfile: %s", err)
			return nil, err

		}
		targets = append(targets, target)
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error while reading targetfile: %s", err)
			return nil, err
		}
	}
	return targets, nil
}
func GetTarget(targetString string) (error, *Target) {
	var target *Target
	targetSlice := strings.Split(targetString, ":")
	if len(targetSlice) == 2 {
		target = InitTarget(targetSlice[0], targetSlice[1])
	} else {
		err := errors.New("Target input string malformed")
		log.Println(err)
		return err, target

	}
	return nil, target
}
func InitTarget(ip, port string) *Target {
	target := Target{
		IP:   ip,
		Port: port,
		CryptoIKEv1: TargetCryptoIKEv1{

			EncAlgos:    make(map[uint16]map[uint16]bool),
			HashAlgos:   make(map[uint16]bool),
			DHGroups:    make(map[uint16]bool),
			AuthMethods: make(map[uint16]bool),
		},
		CryptoIKEv2: TargetCryptoIKEv2{
			EncAlgos:   make(map[uint16]map[uint16]bool),
			PRFAlgos:   make(map[uint16]bool),
			IntegAlgos: make(map[uint16]bool),
			DHGroups:   make(map[uint16]bool),
		},
	}
	return &target
}
func (t *Target) PrintResults() {
	if t.IKEv1Supported {
		t.CryptoIKEv1.PrintResults()
	}
	if t.IKEv2Supported {
		t.CryptoIKEv2.PrintResults()
	}
}

type TargetCryptoIKEv1 struct {
	EncAlgos map[uint16]map[uint16]bool
	//KeyLengths  map[uint16]bool
	HashAlgos   map[uint16]bool
	AuthMethods map[uint16]bool
	DHGroups    map[uint16]bool
}

func (t *TargetCryptoIKEv1) PrintResults() {

	encAlgos := IKEConst.GetIKEv1EncAlgos()
	hashAlgos := IKEConst.GetIKEv1HashAlgos()
	authMethods := IKEConst.GetIKEv1AuthMethods()
	dhGroups := IKEConst.GetIKEv1DHGroups()

	fmt.Printf("\n\n::::::::::::::::::::::::::::::::::::::::::::::::::::")
	fmt.Printf("\n\nFollowing IKEv1 encryption algorithms are supported:\n\n")
	for encAlgo, keyLengths := range t.EncAlgos {
		for keyLength, _ := range keyLengths {

			if keyLength != 0 {
				fmt.Printf("(ID:%d) %s\t KeyLength: %d\n", encAlgo, encAlgos[encAlgo], keyLength)
			} else {
				fmt.Printf("(ID:%d) %s\t \n", encAlgo, encAlgos[encAlgo])
			}

		}
	}

	fmt.Printf("\nFollowing IKEv1 hash algorithms are supported:\n\n")
	for hash, _ := range t.HashAlgos {
		fmt.Printf("(ID:%d) %s\n", hash, hashAlgos[hash])
	}
	fmt.Printf("\nFollowing IKEv1 authentication methods are supported:\n\n")
	for authMethod, _ := range t.AuthMethods {
		fmt.Printf("(ID:%d) %s\n", authMethod, authMethods[authMethod])
	}
	fmt.Printf("\nFollowing IKEv1 key exchange methods are supported:\n\n")
	for dhGroup, _ := range t.DHGroups {
		fmt.Printf("(ID:%d) %s\n", dhGroup, dhGroups[dhGroup])
	}

}
func (t *TargetCryptoIKEv1) AddEnc(algo, keyLength uint16) {

	if t.EncAlgos[algo] == nil {
		t.EncAlgos[algo] = make(map[uint16]bool)
	}
	t.EncAlgos[algo][keyLength] = true

}

func (t *TargetCryptoIKEv1) AddHashAlgo(algo uint16) {
	t.HashAlgos[algo] = true
}

func (t *TargetCryptoIKEv1) AddAuthMethod(method uint16) {
	t.AuthMethods[method] = true
}

func (t *TargetCryptoIKEv1) AddDHGroup(group uint16) {
	t.DHGroups[group] = true
}

type TargetCryptoIKEv2 struct {
	// algo + length
	EncAlgos map[uint16]map[uint16]bool
	//KeyLengths map[uint16]bool
	PRFAlgos   map[uint16]bool
	IntegAlgos map[uint16]bool
	DHGroups   map[uint16]bool
}

func (t *TargetCryptoIKEv2) PrintResults() {

	encAlgos := IKEConst.GetIKEv2EncAlgos()
	integAlgos := IKEConst.GetIKEv2IntegrityAlgos()
	prfAlgos := IKEConst.GetIKEv2PRFAlgos()
	kexAlgos := IKEConst.GetIKEv2KEXMethods()

	fmt.Printf("\n\n::::::::::::::::::::::::::::::::::::::::::::::::::::")
	fmt.Printf("\n\nFollowing IKEv2 encryption algorithms are supported:\n\n")
	for encAlgo, keyLengths := range t.EncAlgos {
		for keyLength, _ := range keyLengths {

			if keyLength != 0 {
				fmt.Printf("(ID:%d) %s\t KeyLength: %d\n", encAlgo, encAlgos[encAlgo], keyLength)
			} else {
				fmt.Printf("(ID:%d) %s\t \n", encAlgo, encAlgos[encAlgo])
			}

		}
	}

	fmt.Printf("\nFollowing IKEv2 pseudorandom algorithms are supported:\n\n")
	for prf, _ := range t.PRFAlgos {
		fmt.Printf("(ID:%d) %s\n", prf, prfAlgos[prf])
	}
	fmt.Printf("\nFollowing IKEv2 integrity algorithms are supported:\n\n")
	for integ, _ := range t.IntegAlgos {
		fmt.Printf("(ID:%d) %s\n", integ, integAlgos[integ])
	}
	fmt.Printf("\nFollowing IKEv2 key exchange methods are supported:\n\n")
	for dhGroup, _ := range t.DHGroups {
		fmt.Printf("(ID:%d) %s\n", dhGroup, kexAlgos[dhGroup])
	}

}
func (t *TargetCryptoIKEv2) AddEnc(algo, keyLength uint16) {
	if t.EncAlgos[algo] == nil {
		t.EncAlgos[algo] = make(map[uint16]bool)
	}
	t.EncAlgos[algo][keyLength] = true
}

func (t *TargetCryptoIKEv2) AddPRF(algo uint16) {
	t.PRFAlgos[algo] = true
}

func (t *TargetCryptoIKEv2) AddInteg(algo uint16) {
	t.IntegAlgos[algo] = true
}

func (t *TargetCryptoIKEv2) AddDHGroup(group uint16) {
	t.DHGroups[group] = true
}
