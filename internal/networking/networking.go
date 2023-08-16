package networking

import (
	"fmt"
	"net"
	"time"
)

func SendIKEPacket(data []byte, sourceip, sourceport string, destip string, destport string, timeout int) ([]byte, error) {
	//connection, err := net.DialTimeout("udp", ip+":"+port, time.Second*2)
	// fixed for now. Get interface from user in later version
	laddr, err := net.ResolveUDPAddr("udp", sourceip+":"+sourceport)
	if err != nil {
		fmt.Println("resolveErrLocal")
		fmt.Println(err)
	}
	raddr, err := net.ResolveUDPAddr("udp", destip+":"+destport)
	if err != nil {
		fmt.Println("resolvErrRemote")
		fmt.Println(err)
	}
	connection, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		fmt.Println(err)
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
