package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/PhilipM-eu/ikepoke/internal/connectionTesting"
	"github.com/PhilipM-eu/ikepoke/internal/exploits"
	ikeoptions "github.com/PhilipM-eu/ikepoke/internal/options"
	"github.com/PhilipM-eu/ikepoke/internal/scanning"
)

func main() {
	selOptions := initFlags()
	flag.Parse()
	//if !ikev1scan && !ikev2scan && !cve202330570 {
	//	help = true
	//}
	if selOptions.Help || (!selOptions.IKEv1 && !selOptions.IKEv2) {

		flag.PrintDefaults()
		return
	}
	// parse the targets. If only a single target was supplied the list will contain only this target.
	targetList, err := selOptions.GetTargets()
	if err != nil {
		fmt.Println("Error while parsing targets. See error log for detail.")
		return
	}
	// test connectivity
	for _, target := range targetList {
		target.IKEv1Supported, target.IKEv2Supported = connectionTesting.TestConnectivity(*target, *selOptions)

	}
	if selOptions.Scan {
		if selOptions.Worker > 1 {
			if selOptions.LocalPort != "" {
				log.Fatalln("Cannot use fixed source port and multiple workers")
			}
			scanning.JobControl(targetList, *selOptions)
		} else {
			for _, target := range targetList {
				scanning.ScanTarget(target, *selOptions)
			}
		}
		// Single transform scan for each target
	} else if selOptions.SingleScan {
		if selOptions.IKEv1 {
			sa, err := selOptions.GetTransformIKEv1()
			if err != nil {
				log.Println(err)
				return
			}

			for _, target := range targetList {
				fmt.Printf("Sending single transform IKEv1 scan of target %s:%s\n \n", target.IP, target.Port)
				err, _, _, _, _, _ := scanning.SendIKEPhase1(selOptions.LocalIP, selOptions.GetPort(), target.IP, target.Port, sa, selOptions.Timeout, selOptions.Verbose)
				if err != nil {
					log.Println(err)
				} else {
					mode := "main"
					if sa.AggressiveMode {
						mode = "aggressive"
					}
					fmt.Printf("Finished single transform scan of target %s:%s\n Support for %d/%d,%d,%d,%d in IKEv1 %s mode  is available\n", target.IP, target.Port, sa.EncAlgo, sa.KeyLength, sa.HashAlgo, sa.AuthMethod, sa.DhGroup, mode)
				}
			}
		}
		if selOptions.IKEv2 {

			sa, err := selOptions.GetTransformIKEv2()
			if err != nil {
				log.Println(err)
				return
			}

			for _, target := range targetList {
				fmt.Printf("Sending single transform IKEv2 scan of target %s:%s\n \n", target.IP, target.Port)
				err, _, _, _, _, _ := scanning.SendSAInitAndGetChosenAlgos(selOptions.LocalIP, selOptions.GetPort(), target.IP, target.Port, sa, selOptions.Timeout, selOptions.Verbose)
				if err != nil {
					log.Println(err)
				} else {

					fmt.Printf("Finished single transform scan of target %s:%s\n Support for %d/%d,%d,%d,%d  in IKEv2 is available\n", target.IP, target.Port, sa.EncAlgo, sa.KeyLength, sa.PRFAlgo, sa.IntegAlgo, sa.DhGroup)
				}
			}
		}
	}
	if selOptions.Cve202330570 && len(targetList) > 0 {
		exploits.CVE202330570(selOptions.LocalIP, selOptions.GetPort(), targetList[0], selOptions.Timeout, selOptions.Verbose)
	}
	if selOptions.Cve202323009 && len(targetList) > 0 {
		if selOptions.PSK == "" {
			fmt.Println("No PSK provided - needed for DoS attempt")
			return
		}
		err := connectionTesting.TestAuthentication(targetList[0], *selOptions)
		if err != nil {
			fmt.Printf("Could not connect and authenticate to target %s. Connection error: %s\nAborting DoS attempt.\n", targetList[0].IP, err)
			return
		}
		exploits.CVE202323009(selOptions.LocalIP, selOptions.GetPort(), targetList[0], []byte(selOptions.PSK), selOptions.Timeout, selOptions.Verbose)
	}
	//target.CryptoIKEv2.AddEnc(20, 256)
	//session.SendIKEv1InitMainMode()
	//session.SendIKEv2Delete()
}
func initFlags() *ikeoptions.Options {
	selectedOptions := ikeoptions.NewOptions()
	flag.StringVar(&selectedOptions.LocalIP, "s", "127.0.0.1", "sets the source IP to be used. This IP also determines the outgoing network interface.")

	flag.StringVar(&selectedOptions.LocalPort, "sport", "", "sets a fixed source port to be usedfor all connections. If none specified each connection uses a random port in the range of 1025-65356. If a port below 1025 is specified, elevated privileges are required.")
	flag.StringVar(&selectedOptions.TargetString, "t", "", "sets the  target to be used. Format: <IP>:<Port>")

	flag.StringVar(&selectedOptions.TransformIKEv1, "transformv1", "", "Sets the single transform to usefor ikev1. Syntax: EncAlgo/KeyLen,HashAlgo,AuthMethod,DHGroup\n Example: 7/256,2,1,14 ")
	flag.StringVar(&selectedOptions.TransformIKEv2, "transformv2", "", "Sets the single transform to use for ikev2. Syntax: EncAlgo/KeyLen,PRFAlgo,IntegAlgo,DHGroup\n Example: 20/256,7,0,14 \n Note that AEAD enc algos such as 14-20 ignore the integrity algorithm. ")
	flag.StringVar(&selectedOptions.PSK, "psk", "", "Sets the Pre-shared key to use for authentication via IKEv2")
	flag.StringVar(&selectedOptions.TargetsFilepath, "f", "", "sets the file path to read a list of targets from. The targets need to be formatted as one <IP>:<Port> per line. ")
	flag.BoolVar(&selectedOptions.Help, "help", false, "Prints the help and exits")
	flag.BoolVar(&selectedOptions.NoDiscovery, "nd", false, "Disable the discovery phase and treat all targets as online.")
	flag.BoolVar(&selectedOptions.Verbose, "v", false, "Sets the output to verbose. More information is displayed.")
	flag.BoolVar(&selectedOptions.IKEv1, "ikev1", false, "Use IKEv1.")
	flag.BoolVar(&selectedOptions.AggressiveMode, "aggressive", false, "Use IKEv1 aggressive mode instead of main mode. Only affects IKEv1 packets in scanmode.")
	flag.BoolVar(&selectedOptions.IKEv2, "ikev2", false, "Use IKEv2.")
	flag.IntVar(&selectedOptions.Timeout, "timeout", 2, "Specifies the network timeout for all connections made in seconds. IKEv1 aggressive mode may need a higher timeout value than other scan modes, depending on the target server.")
	flag.IntVar(&selectedOptions.Worker, "worker", 1, "Specifies the number of workers to concurrently use to perform a scan. If number if 1, the scan will be performed without concurrent mode.")
	flag.BoolVar(&selectedOptions.Scan, "scan", false, "Scan available transforms in IKEv1 or IKEv2 depending on specified mode.")
	flag.BoolVar(&selectedOptions.SingleScan, "single", false, "Scan the transform given with --transformv1 and/or transformv2 against the target in IKEv1 or IKEv2 depending on specified mode.")
	flag.StringVar(&selectedOptions.ScanMode, "scanmode", "common", "Sets the scanmode, choose from \"full\", \"vulnerable\" or \"common\". If none is chosen, \"common\" is used as default.")
	flag.BoolVar(&selectedOptions.Cve202330570, "ikev1dos", false, "Try to trigger a DoS on a libreswan target via the CVE-2023-30570 vulnerability. This option will only affect a singular target. If multiple targets via a targetlist are provided only, the first one will be attacked. ")
	flag.BoolVar(&selectedOptions.Cve202323009, "ikev2dos", false, "Try to trigger a DoS on a libreswan target via the CVE-2023-23009 vulnerability. This option will only affect a singular target. If multiple targets via a targetlist are provided, only the first one will be attacked. ")
	return selectedOptions
}
