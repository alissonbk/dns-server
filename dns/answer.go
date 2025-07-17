package dns

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

/*
Name	Label Sequence	The domain name encoded as a sequence of labels.
Type	2-byte Integer	1 for an A record, 5 for a CNAME record etc., full list here
Class	2-byte Integer	Usually set to 1 (full list here)
TTL (Time-To-Live)	4-byte Integer	The duration in seconds a record can be cached before requerying.
Length (RDLENGTH)	2-byte Integer	Length of the RDATA field in bytes.
Data (RDATA)	Variable	Data specific to the record type.
*/

type Answer struct {
	// an owner name, i.e., the name of the node to which this resource record pertains.
	NAME string
	// two octets containing one of the RR TYPE codes
	TYPE string
	// two octets containing one of the RR CLASS codes.
	CLASS string
	/*
		a 32 bit signed integer that specifies the time interval that the resource record may be cached before the source
		of the information should again be consulted.  Zero values are interpreted to mean that the RR can only be
		used for the transaction in progress, and should not be cached.  For example, SOA records are always distributed
		with a zero TTL to prohibit caching.  Zero values can also be used for extremely volatile data.
		Question: why do they use signed 32 bit if it only accepts positive values?
	*/
	TTL int32
	// an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
	RDLENGTH uint16
	// a variable length string of octets that describes the resource.  The format of this information varies according to the TYPE and CLASS of the resource record.
	// for an A record would be a 4byte ipv4 address
	RDATA string
}

// Useful for debugging and testing, but the client will never send an answer...
func DecodeAnswer(payload []byte, questionSize int) (*Answer, error) {
	// 12 for the header...
	START_POS := 12 + questionSize
	domain, domainSize, err := decodeDomainName(payload[START_POS:])
	if err != nil {
		return nil, fmt.Errorf("failed to decoded the domain, cause: %s", err)
	}

	typePosition := START_POS + domainSize
	ttype, err := getRecordTypeString(binary.BigEndian.Uint16(payload[typePosition:]))
	if err != nil {
		return nil, fmt.Errorf("could not parse the QTYPE, cause: %s", err)
	}

	classPosition := START_POS + domainSize + 2
	class, err := getRecordClassString(binary.BigEndian.Uint16(payload[classPosition:]))
	if err != nil {
		return nil, fmt.Errorf("could not parse the QCLASS, cause: %s", err)
	}

	ttlPosition := START_POS + domainSize + 4
	ttl := binary.BigEndian.Uint32(payload[ttlPosition:])

	rdlengthPosition := START_POS + domainSize + 8
	rdlength := binary.BigEndian.Uint16(payload[rdlengthPosition:])

	rdataPosition := START_POS + domainSize + 10
	endRdataPosition := rdataPosition + int(rdlength)
	rdata := decodeData(payload[rdataPosition:endRdataPosition], int(rdlength))

	return &Answer{
		NAME:     domain,
		TYPE:     ttype,
		CLASS:    class,
		TTL:      int32(ttl),
		RDLENGTH: rdlength,
		RDATA:    rdata,
	}, nil
}

func (a *Answer) EncodeAnswer() ([]byte, error) {
	// DOMAIN
	buf, err := encodeDomainName(a.NAME)
	if err != nil {
		return buf, err
	}

	// TYPE
	recordType, err := getRecordTypeUint16(a.TYPE)
	if err != nil {
		return []byte{}, err
	}
	buf = binary.BigEndian.AppendUint16(buf, recordType)

	// CLASS
	recordClass, err := getRecordClassUint16(a.CLASS)
	if err != nil {
		return []byte{}, err
	}
	buf = binary.BigEndian.AppendUint16(buf, recordClass)

	// TTL
	// not sure about this, this need a signed 32 bit, but the sign should allways be positive (think in binary level can just change the LSB to 1)
	uintTTL := uint32(a.TTL)
	uintTTL |= 1 << 31
	buf = binary.BigEndian.AppendUint32(buf, uint32(a.TTL))

	// RDLENGTH
	buf = binary.BigEndian.AppendUint16(buf, a.RDLENGTH)

	// RDATA
	rdata, err := a.buildData()
	if err != nil {
		return []byte{}, err
	}
	buf = append(buf, rdata...)

	return buf, nil
}

// just checks if the size matches
func (a *Answer) buildData() ([]byte, error) {
	buf, err := bytesFromIPAdress(a.RDATA)
	if err != nil {
		return []byte{}, err
	}

	if len(buf) > int(a.RDLENGTH) {
		return []byte{}, fmt.Errorf("the data section has a bigger size than the specified RDLENGTH")
	}

	return buf, nil
}

func decodeData(buf []byte, length int) string {
	str := ""
	for i := range length {
		str += strconv.Itoa(int(buf[i]))
		if i < length-1 {
			str += "."
		}
	}

	return str
}
