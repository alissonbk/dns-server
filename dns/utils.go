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
func encodeDomainName(name string) ([]byte, error) {
	var buf []byte
	splitted := strings.SplitSeq(name, ".")
	for domainPart := range splitted {
		runes := []rune(domainPart)
		if len(runes) > 63 {
			return []byte{}, fmt.Errorf("the domain part %s has more than 63 octets.", domainPart)
		}
		buf = append(buf, byte(len(runes)))
		for _, r := range runes {
			buf = append(buf, byte(r))
		}

		if len(buf) > 255 {
			return []byte{}, fmt.Errorf("the domain %s has more than 255 octets.", name)
		}
	}

	buf = append(buf, 0x00)
	return buf, nil
}

// will recieve the buffer from 12:n beeing 12 the end of the header section;
// returns the domainName as string, size and error
// dont need to remove the last dot as the real domain name always has this final dot
func decodeDomainName(buf []byte) (string, int, error) {
	str := ""
	curr := 0
	for curr < 256 && buf[curr] != 0x00 {
		n := int(buf[curr])
		if n > 63 {
			return "", 0, fmt.Errorf("label has more than 63 octets.")
		}
		str += string(buf[curr : curr+n+1])
		str += "."
		curr += n + 1
	}

	// taking account the 0x00 byte
	return str, curr + 1, nil
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

func getRecordTypeString(code uint16) (string, error) {
	switch code {
	case 1:
		return "A", nil
	case 2:
		return "NS", nil
	case 3:
		return "MD", nil
	case 4:
		return "MF", nil
	case 5:
		return "CNAME", nil
	case 6:
		return "SOA", nil
	case 7:
		return "MB", nil
	case 8:
		return "MG", nil
	case 9:
		return "MR", nil
	case 10:
		return "NULL", nil
	case 11:
		return "WKS", nil
	case 12:
		return "PTR", nil
	case 13:
		return "HINFO", nil
	case 14:
		return "MINFO", nil
	case 15:
		return "MX", nil
	case 16:
		return "TXT", nil
	case 252:
		return "AXFR", nil
	case 253:
		return "MAILB", nil
	case 254:
		return "MAILA", nil
	case 255:
		return "*", nil
	default:
		return "", fmt.Errorf("invalid record type code: %d", code)
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

func getRecordClassString(code uint16) (string, error) {
	switch code {
	case 1:
		return "IN", nil
	case 2:
		return "CS", nil
	case 3:
		return "CH", nil
	case 4:
		return "HS", nil
	default:
		return "", fmt.Errorf("invalid record class code: %d", code)
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
