package scanning

import (
	"errors"
	"fmt"
	"log"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
	"github.com/PhilipM-eu/ikepoke/internal/IKESession"
	"github.com/PhilipM-eu/ikepoke/internal/IKEv1"
	"github.com/PhilipM-eu/ikepoke/internal/options"
	"github.com/PhilipM-eu/ikepoke/internal/targets"
	"github.com/PhilipM-eu/ikepoke/internal/transforms"
)

type SingleSA interface {
	GetType() int
}
type Scan struct {
	Mode byte
}
type ScanResult struct {
	sa  SingleSA
	ID  int
	err error
}
type ScanJob struct {
	ID         int
	targetIP   string
	targetPort string
	timeout    int
	sa         SingleSA
	ResultChan chan ScanResult
}

func worker(jobChannel <-chan ScanJob, srcIP, srcPort string, verbose bool) {
	for job := range jobChannel {
		var err error = nil
		switch job.sa.GetType() {
		case 0:
			ikev1SA := job.sa.(*transforms.SingleSAIKEv1)
			err, _, _, _, _, _ = SendIKEPhase1(srcIP, srcPort, job.targetIP, job.targetPort, *ikev1SA, job.timeout, verbose)

		case 1:
			ikev2SA := job.sa.(*transforms.SingleSAIKEv2)
			err, _, _, _, _, _ = SendSAInitAndGetChosenAlgos(srcIP, srcPort, job.targetIP, job.targetPort, *ikev2SA, job.timeout, verbose)
		default:
			err = errors.New("Unknown mode")

		}
		job.ResultChan <- ScanResult{sa: job.sa, ID: job.ID, err: err}

	}

}
func JobControl(targets []*targets.Target, selOptions options.Options) {
	if selOptions.Worker < 1 {
		return
	}
	var ikev1SAs []transforms.SingleSAIKEv1 = nil
	var ikev2SAs []transforms.SingleSAIKEv2 = nil
	scan := Scan{Mode: selOptions.GetScanMode()}
	if selOptions.IKEv1 {
		ikev1SAs = scan.GetIKEv1SAs(selOptions.AggressiveMode)
	}
	if selOptions.IKEv2 {
		ikev2SAs = scan.GetIKEv2SAs()
	}
	numberOfJobs := 0
	for _, target := range targets {

		if target.IKEv1Supported {
			numberOfJobs += len(ikev1SAs)
		}
		if target.IKEv2Supported {
			numberOfJobs += len(ikev2SAs)
		}

	}
	if numberOfJobs == 0 {
		log.Println("No targets available to scan")
		return
	}
	// initialise the concurrent workers and the job queue as well as the result queue
	// the job queue needs to be large enough to hold all jobs -> therefore its buffer is the added length of both SA slices times the targets
	jobChannel := make(chan ScanJob, (len(ikev1SAs)+len(ikev2SAs))*len(targets))
	resultChannel := make(chan ScanResult, selOptions.Worker)
	//close channels at the end of the function call
	defer close(jobChannel)
	defer close(resultChannel)

	for i := 0; i < selOptions.Worker; i++ {
		// each worker gets their own port - this will not work with a set src port
		go worker(jobChannel, selOptions.LocalIP, selOptions.GetPort(), selOptions.Verbose)
	}

	jobCounter := 0
	for index, target := range targets {
		if target.IKEv1Supported {
			for _, ikev1sa := range ikev1SAs {
				job := ScanJob{
					ID:         index,
					targetIP:   target.IP,
					targetPort: target.Port,
					timeout:    selOptions.Timeout,
					//
					sa:         ikev1sa.GetCopy(),
					ResultChan: resultChannel,
				}
				jobChannel <- job
				jobCounter++
			}
		}
		if target.IKEv2Supported {

			for _, ikev2sa := range ikev2SAs {

				job := ScanJob{
					ID:         index,
					targetIP:   target.IP,
					targetPort: target.Port,
					timeout:    selOptions.Timeout,
					//
					sa:         ikev2sa.GetCopy(),
					ResultChan: resultChannel,
				}
				jobChannel <- job
				jobCounter++
			}
		}
	}
	fmt.Println("Starting Scan with following parameters:")
	parameters := ""
	if selOptions.IKEv1 {
		parameters += "IKEv1 "
		if selOptions.AggressiveMode {
			parameters += "Aggressive Mode "
		}
	}
	if selOptions.IKEv2 {
		parameters += "IKEv2"
	}
	fmt.Printf("%s\n", parameters)
	if selOptions.Verbose {
		fmt.Printf("\033[s")
	}
	maxJobs := jobCounter
	for result := range resultChannel {
		if result.err == nil && targets[result.ID] != nil {
			target := targets[result.ID]
			switch result.sa.GetType() {
			case 0:
				sa := result.sa.(*transforms.SingleSAIKEv1)
				target.CryptoIKEv1.AddEnc(sa.EncAlgo, sa.KeyLength)
				target.CryptoIKEv1.AddHashAlgo(sa.HashAlgo)
				target.CryptoIKEv1.AddDHGroup(sa.DhGroup)
				target.CryptoIKEv1.AddAuthMethod(sa.AuthMethod)
			case 1:
				sa := result.sa.(*transforms.SingleSAIKEv2)
				target.CryptoIKEv2.AddEnc(sa.EncAlgo, sa.KeyLength)
				target.CryptoIKEv2.AddPRF(sa.PRFAlgo)
				target.CryptoIKEv2.AddInteg(sa.IntegAlgo)
				target.CryptoIKEv2.AddDHGroup(sa.DhGroup)
			default:

			}
		}
		jobCounter--
		if selOptions.Verbose && (maxJobs-jobCounter)%(maxJobs/100) == 0 {
			fmt.Printf("\033[u\033[K")
			fmt.Printf("Status %d of %d Transforms done ", maxJobs-jobCounter, maxJobs)

		}
		if jobCounter <= 0 {
			break
		}
	}

	for _, target := range targets {
		target.PrintResults()
	}
}

// generate the different possible combinations for IKEv1 transforms according to the scanmode
func (s *Scan) GetIKEv1SAs(aggrMode bool) []transforms.SingleSAIKEv1 {
	var encAlgos, hashAlgos, authMethods, dhGroups []uint16
	switch s.Mode {
	//
	case IKEConst.VulnerableScan:
		encAlgos = IKEConst.IKEv1DeprecatedEncAlgos()
		hashAlgos = IKEConst.IKEv1DeprecatedHashAlgos()
		authMethods = IKEConst.IKEv1DeprecatedAuthMethods()
		dhGroups = IKEConst.IKEv1DeprecatedDHGroups()
	case IKEConst.FullScan:

		encAlgos = IKEConst.IKEv1AllEncAlgos()
		hashAlgos = IKEConst.IKEv1AllHashAlgos()
		authMethods = IKEConst.IKEv1AllAuthMethods()
		dhGroups = IKEConst.IKEv1AllDHGroups()
	case IKEConst.CommonScan:
		fallthrough
	default:

		encAlgos = IKEConst.IKEv1CommonEncAlgos()
		hashAlgos = IKEConst.IKEv1CommonHashAlgos()
		authMethods = IKEConst.IKEv1CommonAuthMethods()
		dhGroups = IKEConst.IKEv1CommonDHGroups()
	}
	return genAllPossibleSAsIKEv1(encAlgos, hashAlgos, authMethods, dhGroups, aggrMode)
}

// generate the different possible combinations for IKEv2 transforms according to the scanmode
func (s *Scan) GetIKEv2SAs() []transforms.SingleSAIKEv2 {
	var encAlgos, prfAlgos, integAlgos, kexAlgos []uint16
	switch s.Mode {
	//
	case IKEConst.VulnerableScan:
		encAlgos = IKEConst.IKEv2DeprecatedEncAlgos()
		prfAlgos = IKEConst.IKEv2DeprecatedPRFAlgos()
		integAlgos = IKEConst.IKEv2DeprecatedIntegAlgos()
		kexAlgos = IKEConst.IKEv2DeprecatedKEXAlgos()
	case IKEConst.FullScan:

		encAlgos = IKEConst.IKEv2AllEncAlgos()
		prfAlgos = IKEConst.IKEv2AllPRFAlgos()
		integAlgos = IKEConst.IKEv2AllIntegAlgos()
		kexAlgos = IKEConst.IKEv2AllKEXAlgos()
	case IKEConst.CommonScan:
		fallthrough
	default:

		encAlgos = IKEConst.IKEv2CommonEncAlgos()
		prfAlgos = IKEConst.IKEv2CommonPRFAlgos()
		integAlgos = IKEConst.IKEv2CommonIntegAlgos()
		kexAlgos = IKEConst.IKEv2CommonKEXAlgos()
	}
	return genAllPossibleSAsIKEv2(encAlgos, prfAlgos, integAlgos, kexAlgos)
}
func genAllPossibleSAsIKEv1(encAlgos, hashAlgos, authMethods, dhGroups []uint16, aggrMode bool) []transforms.SingleSAIKEv1 {
	sas := make([]transforms.SingleSAIKEv1, 0)

	for _, enc := range encAlgos {
		keyLengths := IKEConst.GetPossibleKeyLengthsForEncIKEv1(enc)
		for _, keyLength := range keyLengths {
			for _, hashAlgo := range hashAlgos {
				for _, authMethod := range authMethods {
					for _, dhGroup := range dhGroups {
						sa := transforms.SingleSAIKEv1{
							EncAlgo:        enc,
							KeyLength:      keyLength,
							HashAlgo:       hashAlgo,
							DhGroup:        dhGroup,
							AuthMethod:     authMethod,
							AggressiveMode: aggrMode,
						}
						sas = append(sas, sa)
					}
				}
			}
		}
	}
	return sas

}
func genAllPossibleSAsIKEv2(encAlgos, prfAlgos, integAlgos, kexAlgos []uint16) []transforms.SingleSAIKEv2 {
	sas := make([]transforms.SingleSAIKEv2, 0)

	for _, enc := range encAlgos {
		keyLengths := IKEConst.GetPossibleKeyLengthsForEncIKEv2(enc)
		for _, keyLength := range keyLengths {
			for _, kexAlgo := range kexAlgos {
				for _, prfAlgo := range prfAlgos {
					switch enc {
					case 14, 15, 16, 17, 18, 19, 20:
						sa := transforms.SingleSAIKEv2{
							EncAlgo:   enc,
							KeyLength: keyLength,
							PRFAlgo:   prfAlgo,
							DhGroup:   kexAlgo,
							IntegAlgo: 0,
						}
						sas = append(sas, sa)
					default:
						for _, integAlgo := range integAlgos {

							sa := transforms.SingleSAIKEv2{
								EncAlgo:   enc,
								KeyLength: keyLength,
								PRFAlgo:   prfAlgo,
								DhGroup:   kexAlgo,
								IntegAlgo: integAlgo,
							}
							sas = append(sas, sa)
						}
					}
				}
			}
		}
	}
	return sas
}

func ScanTarget(target *targets.Target, selOptions options.Options) {
	//selOptions.LocalIP, selOptions.GetPort()selOptions.IKEv1, selOptions.IKEv2, selOptions.GetScanMode()
	if selOptions.IKEv1 {
		ScanIKEv1(selOptions.LocalIP, selOptions.GetPort(), target, selOptions.Verbose, selOptions.GetScanMode(), selOptions.AggressiveMode, selOptions.Timeout)
	}
	if selOptions.IKEv2 {
		ScanIKEv2(selOptions.LocalIP, selOptions.GetPort(), target, selOptions.Verbose, selOptions.GetScanMode(), selOptions.Timeout)
	}
	target.PrintResults()
}
func ScanIKEv1(srcIP, srcPort string, target *targets.Target, verbose bool, mode byte, aggressiveMode bool, timeout int) {
	if !target.IKEv1Supported {
		fmt.Printf("Target:%s:%s does not support IKEv1 - skipping scan of transforms", target.IP, target.Port)
		return

	}
	scan := Scan{Mode: mode}
	sas := scan.GetIKEv1SAs(aggressiveMode)
	ScanMultipleSAsIKEv1(srcIP, srcPort, target, sas, verbose, timeout)
}
func ScanMultipleSAsIKEv1(srcIP, srcPort string, target *targets.Target, sas []transforms.SingleSAIKEv1, verbose bool, timeout int) {
	fmt.Printf("Starting scan of available IKEv1 transforms for target %s:%s\n", target.IP, target.Port)
	fmt.Printf("\033[s")
	for i, sa := range sas {
		//SendIKEv1InitMainMode
		err, enc, keyLength, hashAlgo, dhGroup, authMethod := SendIKEPhase1(srcIP, srcPort, target.IP, target.Port, sa, timeout, verbose)
		if err == nil {

			target.CryptoIKEv1.AddEnc(enc, keyLength)
			target.CryptoIKEv1.AddHashAlgo(hashAlgo)
			target.CryptoIKEv1.AddDHGroup(dhGroup)
			target.CryptoIKEv1.AddAuthMethod(authMethod)
		}
		if i%(len(sas)/100) == 0 && verbose {
			fmt.Printf("\033[u\033[K")
			fmt.Printf("Status %d of %d IKEv1 Transforms done ", i, len(sas))

		}
	}
	fmt.Printf("\nDone scanning IKEv1 transforms for target: %s:%s\n", target.IP, target.Port)

}
func ScanMultipleSAsIKEv2(srcIP, srcPort string, target *targets.Target, sas []transforms.SingleSAIKEv2, verbose bool, timeout int) {

	fmt.Printf("Starting scan of available IKEv2 transforms for target %s:%s\n", target.IP, target.Port)
	fmt.Printf("\033[s")
	for i, sa := range sas {

		err, enc, keyLength, prf, integ, dhGroup := SendSAInitAndGetChosenAlgos(srcIP, srcPort, target.IP, target.Port, sa, timeout, verbose)
		if err == nil {

			target.CryptoIKEv2.AddEnc(enc, keyLength)
			target.CryptoIKEv2.AddPRF(prf)
			target.CryptoIKEv2.AddInteg(integ)
			target.CryptoIKEv2.AddDHGroup(dhGroup)
		}
		if i%(len(sas)/100) == 0 && verbose {
			fmt.Printf("\033[u\033[K")
			fmt.Printf("Status %d of %d IKEv2 Transforms done ", i, len(sas))

		}
	}

	fmt.Printf("\nDone scanning IKEv2 transforms for target: %s:%s\n", target.IP, target.Port)

}
func ScanIKEv2(srcIP, srcPort string, target *targets.Target, status bool, mode byte, timeout int) {

	if !target.IKEv2Supported {
		fmt.Printf("Target:%s:%s does not support IKEv2 - skipping scan of transforms", target.IP, target.Port)
		return
	}
	scan := Scan{Mode: mode}
	sas := scan.GetIKEv2SAs()
	ScanMultipleSAsIKEv2(srcIP, srcPort, target, sas, status, timeout)

}
func SendIKEPhase1(srcIP, srcPort, targetIP, targetPort string, sa transforms.SingleSAIKEv1, timeout int, verbose bool) (error, uint16, uint16, uint16, uint16, uint16) {

	session := IKESession.NewSession(srcIP, srcPort, targetIP, targetPort, timeout, verbose)
	// 7: 256}, 6, 14, 1)
	var response IKEv1.IKEv1
	var err error

	if sa.AggressiveMode {
		response, err = session.SendIKEv1InitAggressiveMode(map[uint16]uint16{sa.EncAlgo: sa.KeyLength}, sa.HashAlgo, sa.DhGroup, sa.AuthMethod)
	} else {
		response, err = session.SendIKEv1InitMainMode(map[uint16]uint16{sa.EncAlgo: sa.KeyLength}, sa.HashAlgo, sa.DhGroup, sa.AuthMethod)
	}
	if err != nil {
		return err, 0, 0, 0, 0, 0
	}
	// in aggressive mode the host will return an authentication failed notification if the algos are acceptable but other auth than psk is used
	if sa.AggressiveMode {
		if notType, err := response.GetNotifyType(); err == nil && notType == 24 {
			return err, sa.EncAlgo, sa.KeyLength, sa.HashAlgo, sa.DhGroup, sa.AuthMethod
		}
	}
	success, chosenSAs := response.GetSAs()
	if !success {
		return errors.New("No response SAs"), 0, 0, 0, 0, 0

	}
	enc, keyLength, prf, dhGroup, authMethod, _, _ := chosenSAs.GetFirstAlgosIKEv1()
	return err, enc, keyLength, prf, dhGroup, authMethod

}

func SendSAInitAndGetChosenAlgos(srcIP, srcPort, targetIP, targetPort string, sa transforms.SingleSAIKEv2, timeout int, verbose bool) (error, uint16, uint16, uint16, uint16, uint16) {

	session := IKESession.NewSession(srcIP, srcPort, targetIP, targetPort, timeout, verbose)
	err, response := session.SendIKEv2SA(map[uint16]uint16{sa.EncAlgo: sa.KeyLength}, sa.PRFAlgo, sa.IntegAlgo, sa.DhGroup)
	if err != nil {
		return err, 0, 0, 0, 0, 0
	}
	success, chosenSAs := response.GetSAs()
	if !success {
		return errors.New("No response SAs"), 0, 0, 0, 0, 0

	}
	enc, keyLength, prf, integ, dhGroup := chosenSAs.GetFirstAlgosIKEv2()
	return err, enc, keyLength, prf, integ, dhGroup
}
