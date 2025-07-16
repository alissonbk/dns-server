package dns

import (
	"fmt"
	"strconv"
	"strings"
)

// Add trailling zeros in the beginning of the hex
func FormatHexTraillingZeros(hex string, desiredLength int) string {
	formatted := ""
	for len([]rune(formatted)) < desiredLength-1 {
		formatted += "0"
	}
	formatted += hex
	return formatted
}

// Domain name is encoded as a sequence of labels
// Labels are encoded as <length><content>
// Length is a single byte representing the length of the label/content
// content has size length in bytes
// sequence of labels is terminated by a null byte \x00
// google.com -> \x06google\x03com\x00 -> 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 -> label 1: \x06google, label 2: \x03com, null byte: \x00
// TODO: DNS labels have a 63 octets limit
// TODO: names have a 255 octets limit
func bytesFromDomainName(name string) []byte {
	var buf []byte
	splitted := strings.SplitSeq(name, ".")
	for domainPart := range splitted {
		runes := []rune(domainPart)
		buf = append(buf, byte(len(runes)))
		for _, r := range runes {
			buf = append(buf, byte(r))
		}
	}
	buf = append(buf, 0x00)

	return buf
}

func getRecordTypeUint16(recordType string) (uint16, error) {
	switch strings.ToUpper(recordType) {
	case "A":
		return 1, nil
	case "NS":
		return 2, nil
	case "MD":
		return 3, nil
	case "MF":
		return 4, nil
	case "CNAME":
		return 5, nil
	case "SOA":
		return 6, nil
	case "MB":
		return 7, nil
	case "MG":
		return 8, nil
	case "MR":
		return 9, nil
	case "NULL":
		return 10, nil
	case "WKS":
		return 11, nil
	case "PTR":
		return 12, nil
	case "HINFO":
		return 13, nil
	case "MINFO":
		return 14, nil
	case "MX":
		return 15, nil
	case "TXT":
		return 16, nil
	case "AXFR":
		return 252, nil
	case "MAILB":
		return 253, nil
	case "MAILA":
		return 254, nil
	case "*":
		return 255, nil
	default:
		return 0, fmt.Errorf("invalid question QTYPE, could not parse")
	}
}

func getRecordClassUint16(class string) (uint16, error) {
	switch strings.ToUpper(class) {
	case "IN":
		return 1, nil
	case "CS":
		return 2, nil
	case "CH":
		return 3, nil
	case "HS":
		return 4, nil
	default:
		return 0, fmt.Errorf("invalid question QCLASS, could not parse")
	}
}

func bytesFromIPAdress(ipaddr string) ([]byte, error) {
	var buf []byte
	for s := range strings.SplitSeq(ipaddr, ".") {
		number, err := strconv.Atoi(s)
		if err != nil {
			return []byte{}, err
		}
		buf = append(buf, byte(number))
	}

	return buf, nil
}
