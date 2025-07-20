package dns

import (
	"encoding/binary"
	"fmt"
	"iter"
	"slices"
	"strings"
)

/*
Record types:

	-TYPE           -value and meaning
	A               1 a host address
	NS              2 an authoritative name server
	MD              3 a mail destination (Obsolete - use MX)
	MF              4 a mail forwarder (Obsolete - use MX)
	CNAME           5 the canonical name for an alias
	SOA             6 marks the start of a zone of authority
	MB              7 a mailbox domain name (EXPERIMENTAL)
	MG              8 a mail group member (EXPERIMENTAL)
	MR              9 a mail rename domain name (EXPERIMENTAL)
	NULL            10 a null RR (EXPERIMENTAL)
	WKS             11 a well known service description
	PTR             12 a domain name pointer
	HINFO           13 host information
	MINFO           14 mailbox or mail list information
	MX              15 mail exchange
	TXT             16 text strings

QTYPE values (all normal Record types are valid as QTYPEs):

	AXFR            252 A request for a transfer of an entire zone
	MAILB           253 A request for mailbox-related records (MB, MG or MR)
	MAILA           254 A request for mail agent RRs (Obsolete - see MX)
	*               255 A request for all records

Classes:

	Classes are:
	IN              1 the Internet
	CS              2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	CH              3 the CHAOS class
	HS              4 Hesiod [Dyer 87]
*/
type Question struct {
	// Domain name, see { utils.formatDomainName }
	QNAME string
	// Record type (16 bits)
	QTYPE string
	// Class  (16 bits)
	QCLASS string
	/**
	* FIXME: need to try to compress every question, and handle cases that it can't
	* compress the domain name (need to have QNAME matching previous QNAME questions in the payload context)
	* the order of the questions will mater as it points to a location in the full payload, it cannot point to the "future",
	* so to compress need to have matching names before the question
	 */
	Compress bool
	// Useful to facilitate using pointer in the compression
	DomainNameSize int
	// Useful to know the boundaries of the question section in the payload as QNAME have dynamic size
	Size int
}

func DecodeQuestions(payload []byte, qdcount int) ([]*Question, error) {
	questions := make([]*Question, qdcount)

	for i := range qdcount {
		previousPayloadOffset := sumQuestionPayloadOffsetUntilIdx(questions, i)
		startPos := previousPayloadOffset

		// check for pointers
		firstByte := payload[startPos]
		flaggedAsCompressed := firstByte>>6 == 0x03
		if flaggedAsCompressed {
			// pointer
			startPos = int(firstByte & 0x3F)
		}

		domain, domainSize, err := decodeDomainName(payload[startPos:])
		if err != nil {
			return nil, fmt.Errorf("failed to decode domain name, cause: %s", err)
		}

		if flaggedAsCompressed {
			domainSize = 1
		}

		typePosition := previousPayloadOffset + domainSize
		qtype, err := getRecordTypeString(binary.BigEndian.Uint16(payload[typePosition:]))
		if err != nil {
			return nil, fmt.Errorf("could not parse the QTYPE, cause: %s", err)
		}

		classPosition := previousPayloadOffset + domainSize + 2
		class, err := getRecordClassString(binary.BigEndian.Uint16(payload[classPosition:]))
		if err != nil {
			return nil, fmt.Errorf("could not parse the QCLASS, cause: %s", err)
		}

		questions[i] = &Question{
			QNAME:          domain,
			QTYPE:          qtype,
			QCLASS:         class,
			DomainNameSize: domainSize,
			Size:           domainSize + 4,
			Compress:       flaggedAsCompressed,
		}
	}

	return questions, nil
}

func EncodeQuestions(questions []*Question) ([]byte, error) {
	var buf []byte
	for i, question := range questions {
		// still need to handle the case where it has a sequence of labels, ending with a pointer
		if (*question).Compress {
			filteredQuestions := filterIndexOut(questions, i)
			parentQuestionIdx := slices.IndexFunc(filteredQuestions, func(q *Question) bool {
				return strings.Contains(q.QNAME, question.QNAME) || strings.Contains(question.QNAME, q.QNAME)
			})

			parentQuestion := questions[parentQuestionIdx]

			pointerOffset := findCompressionPointerOffset(
				strings.SplitSeq(parentQuestion.QNAME, "."),
				strings.Split(question.QNAME, "."),
				sumQuestionPayloadOffsetUntilIdx(questions, parentQuestionIdx),
			)

			// set 2 first bits to 1 as the flag to identify a compression pointer
			pointerOffset |= 1 << 7
			pointerOffset |= 1 << 6

			compressedBytes, err := handleBiggerCompressionDomainName(parentQuestion.QNAME, question.QNAME, byte(pointerOffset))
			if err != nil {
				return []byte{}, fmt.Errorf("failed to handle bigger compression domain, cause: %s", err)
			}

			b, err := question.EncodeQuestion(compressedBytes)
			if err != nil {
				return []byte{}, err
			}

			question.Size = len(b)
			buf = append(buf, b...)
			continue
		}
		b, err := question.EncodeQuestion([]byte{})
		if err != nil {
			return []byte{}, err
		}
		question.Size = len(b)
		buf = append(buf, b...)

	}

	return buf, nil
}

// should be private after fix testings
func (q *Question) EncodeQuestion(compressedQNAME []byte) ([]byte, error) {
	var buf []byte
	domainSize := 0
	if len(compressedQNAME) > 0 {
		buf = compressedQNAME
		domainSize = 1
	} else {
		b, err := encodeDomainName(q.QNAME)
		if err != nil {
			return buf, err
		}
		domainSize = len(b)
		buf = b
	}
	q.DomainNameSize = domainSize

	qtype, err := getRecordTypeUint16(q.QTYPE)
	if err != nil {
		return buf, err
	}
	buf = binary.BigEndian.AppendUint16(buf, qtype)

	qclass, err := getRecordClassUint16(q.QCLASS)
	if err != nil {
		return buf, err
	}
	buf = binary.BigEndian.AppendUint16(buf, qclass)

	return buf, nil
}

// payloadOffset is the offset relative to all the message before the starting point of the parentPayload which contains the domain name
func findCompressionPointerOffset(splitParent iter.Seq[string], splitCompressing []string, payloadOffset int) int {
	const lengthByte = 1
	discardSize := 0
	for parentPart := range splitParent {
		for _, compressingPart := range splitCompressing {
			if parentPart == compressingPart {
				if discardSize > 0 {
					fmt.Println("here")
					return payloadOffset + discardSize
				}
				return payloadOffset + discardSize
			}
		}

		discardSize += len([]rune(parentPart)) + lengthByte
	}

	return -1
}

// handles the case where the compressed have a bigger domain name than the parent
// (the pointer it's always in the end, as it will have the null byte)
func handleBiggerCompressionDomainName(parentDomain string, compressingDomain string, formattedPointer byte) ([]byte, error) {
	if len([]rune(parentDomain)) >= len([]rune(compressingDomain)) {
		return []byte{formattedPointer}, nil
	}

	remainingPart := strings.ReplaceAll(compressingDomain, parentDomain, "")
	encodedPart, err := encodeDomainName(remainingPart)
	if err != nil {
		return []byte{}, err
	}

	encodedPart = encodedPart[:len(encodedPart)-1]
	encodedPart[len(encodedPart)-1] = formattedPointer
	return encodedPart, nil
}

func sumQuestionPayloadOffsetUntilIdx(questions []*Question, idx int) int {
	const headerSize = 12
	s := 0
	for i := range idx {
		s += questions[i].Size
	}

	return s + headerSize
}
