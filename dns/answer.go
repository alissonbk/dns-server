package dns

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strconv"
	"strings"
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
	// Makes compression easier as NAME and RDATA has a dynamic size
	Size int
	// Should compress domain name
	Compress bool
}

// Useful for debugging and testing, but the client will never send an answer...
func DecodeAnswers(payload []byte, questions []*Question, ancount int) ([]Answer, error) {
	answers := make([]Answer, ancount)

	for i := range ancount {
		previousPayloadOffset := sumAnswerPayloadOffsetUntilIdx(answers, questions, i)
		startPos := previousPayloadOffset

		domain, domainSize, useCompression, err := decodeDomainName(payload, startPos)
		if err != nil {
			return nil, fmt.Errorf("failed to decoded the domain, cause: %s", err)
		}

		typePosition := previousPayloadOffset + domainSize
		ttype, err := getRecordTypeString(binary.BigEndian.Uint16(payload[typePosition:]))
		if err != nil {
			return nil, fmt.Errorf("could not parse the QTYPE, cause: %s", err)
		}

		classPosition := previousPayloadOffset + domainSize + 2
		class, err := getRecordClassString(binary.BigEndian.Uint16(payload[classPosition:]))
		if err != nil {
			return nil, fmt.Errorf("could not parse the QCLASS, cause: %s", err)
		}

		ttlPosition := previousPayloadOffset + domainSize + 4
		ttl := binary.BigEndian.Uint32(payload[ttlPosition:])

		rdlengthPosition := previousPayloadOffset + domainSize + 8
		rdlength := binary.BigEndian.Uint16(payload[rdlengthPosition:])

		rdataPosition := previousPayloadOffset + domainSize + 10
		endRdataPosition := rdataPosition + int(rdlength)
		rdata := decodeData(payload[rdataPosition:endRdataPosition], int(rdlength))

		answers[i] = Answer{
			NAME:     domain,
			TYPE:     ttype,
			CLASS:    class,
			TTL:      int32(ttl),
			RDLENGTH: rdlength,
			RDATA:    rdata,
			Size:     domainSize + 2 + 2 + 4 + 2 + 4,
			Compress: useCompression,
		}
	}
	return answers, nil
}

func EncodeAnswers(answers []Answer, questions []*Question) ([]byte, error) {
	var buf []byte
	for i, answer := range answers {
		if answer.Compress {
			filteredAnswers := filterIndexOut(answers, i)
			parentAnswerIdx := slices.IndexFunc(filteredAnswers, func(a Answer) bool {
				return strings.Contains(a.NAME, answer.NAME)
			})
			parentAnswer := answers[parentAnswerIdx]

			pointerOffset := findCompressionPointerOffset(
				strings.SplitSeq(parentAnswer.NAME, "."),
				strings.Split(answer.NAME, "."),
				sumAnswerPayloadOffsetUntilIdx(answers, questions, parentAnswerIdx),
			)

			// set 2 first bits to 1 as the flag to identify a compression pointer
			pointerOffset |= 1 << 7
			pointerOffset |= 1 << 6

			b, err := answer.EncodeAnswer([]byte{byte(pointerOffset)})
			if err != nil {
				return []byte{}, err
			}

			buf = append(buf, b...)
			continue
		}
		encoded, err := answer.EncodeAnswer([]byte{})
		if err != nil {
			return []byte{}, err
		}
		buf = append(buf, encoded...)
	}

	return buf, nil
}

func (a *Answer) EncodeAnswer(compressedDomain []byte) ([]byte, error) {
	var buf []byte
	domainSize := 0
	// DOMAIN
	if len(compressedDomain) > 0 {
		buf = compressedDomain
		domainSize = 1
	} else {
		b, err := encodeDomainName(a.NAME)
		if err != nil {
			return buf, err
		}
		domainSize = len(b)
		buf = b
	}

	fmt.Println("encoded domainsize: ", domainSize)

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

func sumAnswerPayloadOffsetUntilIdx(answers []Answer, questions []*Question, idx int) int {
	questionsSize := sumQuestionPayloadOffsetUntilIdx(questions, len(questions))
	s := 0
	for i := range idx {
		s += answers[i].Size
	}

	return s + questionsSize
}
