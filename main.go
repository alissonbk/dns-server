package main

import (
	"fmt"
	"net"

	"github.com/alissonbk/dns-server/dns"
)

func createStaticMessage() *dns.Message {
	header := dns.Header{
		ID:      1234,
		QR:      true,
		OPCODE:  0,
		AA:      false,
		TC:      false,
		RD:      false,
		RA:      false,
		Z:       0,
		RCODE:   0,
		QDCOUNT: 2,
		ANCOUNT: 2,
		NSCOUNT: 0,
		ARCOUNT: 0,
	}
	question1 := &dns.Question{
		QNAME:    "fodase.google.com",
		QTYPE:    "A",
		QCLASS:   "IN",
		Compress: false,
	}
	question2 := &dns.Question{
		QNAME:    "google.com",
		QTYPE:    "NULL",
		QCLASS:   "IN",
		Compress: true,
	}
	answer1 := dns.Answer{
		NAME:     "fodase.google.com",
		TYPE:     "A",
		CLASS:    "IN",
		TTL:      60,
		RDLENGTH: 4,
		RDATA:    "4.4.4.4",
	}
	answer2 := dns.Answer{
		NAME:     "google.com",
		TYPE:     "SOA",
		CLASS:    "IN",
		TTL:      60,
		RDLENGTH: 4,
		RDATA:    "8.8.8.8",
		Compress: true,
	}

	return &dns.Message{
		Header:    header,
		Questions: []*dns.Question{question1, question2},
		Answers:   []dns.Answer{answer1, answer2},
	}

}

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
	staticResponse, err := createStaticMessage().EncodeMessage()
	if err != nil {
		panic("could not build the static response, cause: " + err.Error())
	}
	decodedMessage, err := dns.DecodeMessage(staticResponse)
	if err != nil {
		panic("could not decode the static response, cause: " + err.Error())
	}
	fmt.Println("decoded message ", decodedMessage)

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
