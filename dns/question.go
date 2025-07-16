package dns

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
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
	// Useful to know the boundaries of the question section in the payload as QNAME have dynamic size
	Size int
}

func DecodeQuestion(payload []byte) (*Question, error) {
	const START_POS = 12
	domain, domainSize, err := decodeDomainName(payload[START_POS:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode domain name, cause: %s", err)
	}

	typePosition := START_POS + (domainSize - 1)
	qtype, err := getRecordTypeString(binary.BigEndian.Uint16(payload[typePosition:]))
	if err != nil {
		return nil, fmt.Errorf("could not parse the QTYPE, cause: %s", err)
	}

	classPosition := START_POS + (domainSize - 1) + 2
	class, err := getRecordClassString(binary.BigEndian.Uint16(payload[classPosition:]))
	if err != nil {
		return nil, fmt.Errorf("could not parse the QCLASS, cause: %s", err)
	}
	return &Question{
		QNAME:  domain,
		QTYPE:  qtype,
		QCLASS: class,
		Size:   domainSize + 4,
	}, nil
}

func (q *Question) EncodeQuestion() ([]byte, error) {
	buf, err := bytesFromDomainName(q.QNAME)
	if err != nil {
		return buf, err
	}

	qtype, err := getRecordTypeUint16(q.QTYPE)
	if err != nil {
		return buf, err
	}
	buf = append(buf, binary.BigEndian.AppendUint16(buf, qtype)...)

	qclass, err := getRecordClassUint16(q.QCLASS)
	if err != nil {
		return buf, err
	}
	buf = append(buf, binary.BigEndian.AppendUint16(buf, qclass)...)

	fmt.Println("question: ", buf[:])
	fmt.Println("question encoded: ", hex.EncodeToString(buf[:]))
	return buf, nil
}
