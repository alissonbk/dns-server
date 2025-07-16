package main

import (
	"fmt"
	"net"

	"github.com/alissonbk/dns-server/dns"
)

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)
	header := &dns.Header{
		ID:      1234,
		QR:      true,
		OPCODE:  0,
		AA:      false,
		TC:      false,
		RD:      false,
		RA:      false,
		Z:       0,
		RCODE:   0,
		QDCOUNT: 1,
		ANCOUNT: 1,
		NSCOUNT: 0,
		ARCOUNT: 0,
	}
	question := &dns.Question{
		QNAME:  "google.com",
		QTYPE:  "A",
		QCLASS: "IN",
	}
	answer := &dns.Answer{
		NAME:     "google.com",
		TYPE:     "A",
		CLASS:    "IN",
		TTL:      60,
		RDLENGTH: 4,
		RDATA:    "8.8.8.8",
	}

	message := &dns.Message{
		Header:   header,
		Question: question,
		Answer:   answer,
	}

	staticResponse, err := message.EncodeMessage()
	if err != nil {
		panic("could not build the static response, cause: " + err.Error())
	}
	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		payload := buf[:size]
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, string(payload))

		decodedMessage, err := dns.DecodeMessage(payload)
		if err != nil {
			fmt.Println("failed to decode the recieved payload, cause: ", err.Error())
		}

		fmt.Printf("decoded message: %v\n", decodedMessage)

		_, err = udpConn.WriteToUDP(staticResponse, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
