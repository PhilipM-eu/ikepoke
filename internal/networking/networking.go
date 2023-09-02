package networking

import (
	"log"
	"net"
	"time"
)

func SendIKEPacket(data []byte, sourceip, sourceport string, destip string, destport string, timeout int) ([]byte, error) {
	//connection, err := net.DialTimeout("udp", ip+":"+port, time.Second*2)
	// fixed for now. Get interface from user in later version
	laddr, err := net.ResolveUDPAddr("udp", sourceip+":"+sourceport)
	if err != nil {

		log.Printf("Could not resolve local address %s\n", err)
	}
	raddr, err := net.ResolveUDPAddr("udp", destip+":"+destport)
	if err != nil {
		log.Printf("Could not resolve remote address %s\n", err)
	}
	connection, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {

		log.Printf("Error during connection setup %s\n", err)
		return nil, err
	}
	defer connection.Close()
	_, err = connection.Write(data)
	if err != nil {
		return nil, err
	}
	connection.SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
	resBuf := make([]byte, 2048)
	_, err = connection.Read(resBuf)

	return resBuf, err
}
