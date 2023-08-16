package options

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
	"github.com/PhilipM-eu/ikepoke/internal/targets"
	"github.com/PhilipM-eu/ikepoke/internal/transforms"
)

type Options struct {
	LocalIP         string
	LocalPort       string
	IKEv1           bool
	AggressiveMode  bool
	IKEv2           bool
	TargetString    string
	TargetsFilepath string
	Scan            bool
	ScanMode        string
	Cve202330570    bool
	Cve202323009    bool
	PSK             string
	Help            bool
	Verbose         bool
	Timeout         int
	Worker          int
	TransformIKEv1  string
	TransformIKEv2  string
	SingleScan      bool
	NoDiscovery     bool
}

func NewOptions() *Options {
	return &Options{}

}
func (o *Options) GetTransformIKEv1() (transforms.SingleSAIKEv1, error) {
	if o.TransformIKEv1 == "" {

		return transforms.SingleSAIKEv1{}, errors.New("Trying to parse IKEv1 transform, but none given")
	}
	if !o.IKEv1 && o.TransformIKEv1 != "" {
		return transforms.SingleSAIKEv1{}, errors.New("IKEv1 transform defined but not ikev1 mode")

	}
	return transforms.ParseTargetTransformIKEv1(o.TransformIKEv1, o.AggressiveMode)

}
func (o *Options) GetTransformIKEv2() (transforms.SingleSAIKEv2, error) {
	if o.TransformIKEv2 == "" {

		return transforms.SingleSAIKEv2{}, errors.New("Trying to parse IKEv2 transform, but none given")
	}
	if !o.IKEv2 && o.TransformIKEv2 != "" {
		return transforms.SingleSAIKEv2{}, errors.New("IKEv2 transform defined but not ikev2 mode")

	}
	return transforms.ParseTargetTransformIKEv2(o.TransformIKEv2)

}
func (o *Options) GetScanMode() byte {
	var scanmode byte
	switch o.ScanMode {
	case "full":
		scanmode = IKEConst.FullScan
	case "vulnerable":
		scanmode = IKEConst.VulnerableScan
	default:
		scanmode = IKEConst.CommonScan

	}
	return scanmode

}
func (o *Options) GetPort() string {
	minPort := 1025
	maxPort := 65535
	if o.LocalPort != "" {
		port, err := strconv.Atoi(o.LocalPort)
		if err != nil {
			log.Fatalf("Failure parsing specified port: %s", o.LocalPort)
		}
		if port < minPort && os.Geteuid() != 0 {
			log.Fatalf("Elevated privileges required but not given to use port: %s", o.LocalPort)
		}
		return o.LocalPort
	}
	port := rand.Intn(maxPort-minPort) + minPort
	return fmt.Sprint(port)
}

func (o *Options) GetTargets() ([]*targets.Target, error) {
	var targetList []*targets.Target = nil
	if o.TargetString == "" && o.TargetsFilepath == "" {
		return nil, errors.New("No target input provided")
	}

	if o.TargetString != "" && o.TargetsFilepath != "" {
		return nil, errors.New("Target information provided via both \"-f\" and \"-t\". Please only use one of those options at a time.")
	}
	if o.TargetString != "" {
		err, target := targets.GetTarget(o.TargetString)
		if err != nil {
			log.Printf("Can't parse the provided target input: %s", o.TargetString)
			return nil, err
		}
		targetList = []*targets.Target{target}
	}
	if o.TargetsFilepath != "" {
		var err error
		targetList, err = targets.ReadTargetfile(o.TargetsFilepath)
		if err != nil {

			log.Printf("Can't parse the provided target input file: %s", o.TargetsFilepath)
			return nil, err
		}
	}

	return targetList, nil
}
