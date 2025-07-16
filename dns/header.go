package dns

import (
	"encoding/binary"
	"fmt"
)

// Header is always 12 bytes long (BigEndian encoding)
type EndodedHeader = [12]byte

type Header struct {
	// Packet identifier (16 bits)
	ID uint16
	// Query/Response Indicator (1 bit)
	QR bool
	// Operation Code (4 bits)
	OPCODE uint16
	// Authoritative Answer (1 bit)
	AA bool
	// Truncation (1 bit)
	TC bool
	// Recursion Desired (1 bit)
	RD bool
	// Recursion Available (1 bit)
	RA bool
	// Reserved (3 bits)
	Z uint16
	// Response Code (4 bits)
	RCODE uint16
	// Question Count (16 bits)
	QDCOUNT uint16
	// Answer Record Count (16 bits)
	ANCOUNT uint16
	// Authority Record Count (16 bits)
	NSCOUNT uint16
	// Additional Record Count (16 bits)
	ARCOUNT uint16
}

func DecodeHeader(payload []byte) (*Header, error) {
	header := &Header{
		ID:      binary.BigEndian.Uint16(payload),
		QDCOUNT: binary.BigEndian.Uint16(payload[4:6]),
		ANCOUNT: binary.BigEndian.Uint16(payload[6:8]),
		NSCOUNT: binary.BigEndian.Uint16(payload[8:10]),
		ARCOUNT: binary.BigEndian.Uint16(payload[10:12]),
	}
	header.decodeFlags(payload[2:4])
	return header, nil
}

func (h *Header) EncodeHeader() ([]byte, error) {
	var buf EndodedHeader
	//ID
	binary.BigEndian.PutUint16(buf[0:2], h.ID)
	// 2nd Section (16 bit flags)
	flags, err := h.encodeFlags()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to set header flags, cause: %e", err)
	}

	binary.BigEndian.PutUint16(buf[2:4], flags)
	binary.BigEndian.PutUint16(buf[4:6], h.QDCOUNT)
	binary.BigEndian.PutUint16(buf[6:8], h.ANCOUNT)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCOUNT)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCOUNT)

	return buf[:], nil
}

func (h *Header) decodeFlags(flags []byte) {
	num := binary.BigEndian.Uint16(flags)
	// QR (1bit)
	h.QR = (num>>15)&1 == 1
	// OPCODE (4bit)
	h.OPCODE = (num >> 11 & 0xF)
	// AA (1bit)
	h.AA = num>>10 == 1
	// TC (1bit)
	h.TC = num>>9 == 1
	// RD (1bit)
	h.RD = num>>8 == 1
	// RA (1bit)
	h.RA = num>>7 == 1
	// Z (3 bits)
	h.Z = (num >> 4 & 0x8)
	// RCODE (4 bits)
	h.RCODE = (num & 0xF)
}

// Build the second section of the header (16 bits)
// This works if os arch uses little endian for uints...
func (h *Header) encodeFlags() (uint16, error) {
	var flags uint16

	// Set QR
	if h.QR {
		flags |= 1 << 15
	}

	// Set OPCODE
	// Only from 0-15 (4 bits)
	flags |= uint16(h.OPCODE&0xF) << 11

	// Set AA TC RD RA
	if h.AA {
		flags |= 1 << 10
	}
	if h.TC {
		flags |= 1 << 9
	}
	if h.RD {
		flags |= 1 << 8
	}
	if h.RA {
		flags |= 1 << 7
	}

	// Set Reserved (Z)
	// Only from 0-8 (3 bits)
	flags |= uint16(h.Z&0x8) << 4

	// Set Response code (RCODE)
	// Only from 0-15 (4 bits)
	flags |= uint16(h.RCODE & 0xF)

	return flags, nil
}
