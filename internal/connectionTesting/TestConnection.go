package connectionTesting

import (
	"errors"
	"fmt"
	"net"

	"github.com/PhilipM-eu/ikepoke/internal/IKEConst"
	"github.com/PhilipM-eu/ikepoke/internal/IKESession"
	"github.com/PhilipM-eu/ikepoke/internal/options"
	"github.com/PhilipM-eu/ikepoke/internal/targets"
)

func TestConnectivity(target targets.Target, selOptions options.Options) (bool, bool) {
	var ikev1Supported, ikev2Supported bool
	if selOptions.IKEv1 {
		ikev1Supported = selOptions.NoDiscovery || testConnectivityIKEv1(target, selOptions.LocalIP, selOptions.GetPort(), selOptions.Timeout, selOptions.AggressiveMode, selOptions.Verbose)
	}
	if selOptions.IKEv2 {
		ikev2Supported = selOptions.NoDiscovery || testConnectivityIKEv2(target, selOptions.LocalIP, selOptions.GetPort(), selOptions.Timeout, selOptions.Verbose)
	}

	return ikev1Supported, ikev2Supported
}
func testConnectivityIKEv2(target targets.Target, localIP, localPort string, timeout int, verbose bool) bool {
	fmt.Println("Testing connectivity via IKEv2")
	for i := 0; i < 3; i++ {

		session := IKESession.NewSession(localIP, localPort, target.IP, target.Port, timeout, verbose)
		err, _ := session.SendIKEv2SA(map[uint16]uint16{20: 256}, 7, 0, 14)
		if err == nil {
			fmt.Printf("IKEv2 Response received\n\n\n")
			return true
		} else {
			fmt.Println(err)
		}

	}
	fmt.Printf("No IKEv2 Response received - Target unreachable\n\n\n")
	return false

}
func testConnectivityIKEv1(target targets.Target, localIP, localPort string, timeout int, aggressiveMode, verbose bool) bool {
	fmt.Println("Testing connectivity via IKEv1")
	for i := 0; i < 3; i++ {

		session := IKESession.NewSession(localIP, localPort, target.IP, target.Port, timeout, verbose)
		var err error = nil
		if aggressiveMode {

			_, err = session.SendIKEv1InitAggressiveMode(map[uint16]uint16{5: 0}, 2, 14, 1)
		} else {

			_, err = session.SendIKEv1InitMainMode(map[uint16]uint16{5: 0}, 2, 5, 3)

		}
		if err == nil {
			fmt.Printf("IKEv1 Response received\n\n\n")
			return true
		} else {
			fmt.Println(err)
		}

	}
	fmt.Printf("No IKEv1 Response received - Target unreachable\n\n\n")
	return false

}
func TestAuthentication(target *targets.Target, selOptions options.Options) error {

	session := IKESession.NewSession(selOptions.LocalIP, selOptions.GetPort(), target.IP, target.Port, selOptions.Timeout, selOptions.Verbose)
	sourceIP := net.ParseIP(selOptions.LocalIP)
	if sourceIP == nil {

		fmt.Println("could not parse provided source IP address")
		return errors.New("Source IP is invalid")
	}

	success := session.ConnectToTargetIKEv2()
	if !success {

		return errors.New("Initial connection to authentication target unsuccessful")
	}
	auth := IKESession.Auth{

		PSK:         []byte(selOptions.PSK),
		IDType:      1,
		ID:          sourceIP.To4(),
		TSiSourceIP: sourceIP.To4(),
		TSrStartIP:  []byte{0, 0, 0, 0},
		TSrEndIP:    []byte{255, 255, 255, 255},
	}
	//	session.PrintSessionKeys()
	err, resp := session.SendIKEv2AUTH(auth)
	if err == nil && resp.GetFirstPayloadNextPayload() == IKEConst.IDr {
		session.SendIKEv2Delete(true)
	} else {
		return errors.New("Authentication unsuccessful")
	}
	return nil
}
