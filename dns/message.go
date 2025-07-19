package dns

import (
	"encoding/hex"
	"fmt"
)

type Message struct {
	Header    Header
	Questions []*Question
	Answers   []Answer
}

func DecodeMessage(payload []byte) (*Message, error) {
	message := &Message{}
	decodedHeader, err := DecodeHeader(payload)
	if err != nil {
		return message, err
	}
	message.Header = decodedHeader
	fmt.Printf("decoded header %v\n", decodedHeader)

	decodedQuestions, err := DecodeQuestions(payload, int(decodedHeader.QDCOUNT))
	if err != nil {
		return message, err
	}
	message.Questions = decodedQuestions
	fmt.Println("decoded questions ", decodedQuestions)

	// FIXME: handle multiple and fix start size from multiple questions
	decodedAnswers, err := DecodeAnswers(payload, decodedQuestions, int(decodedHeader.ANCOUNT))
	if err != nil {
		return message, err
	}
	fmt.Println("decoded answers ", decodedAnswers)
	message.Answers = decodedAnswers

	return message, nil
}

func (m *Message) EncodeMessage() ([]byte, error) {
	fmt.Println("message: ", m)
	buf, err := m.Header.EncodeHeader()
	if err != nil {
		return []byte{}, err
	}
	// fmt.Println("header: ", buf)
	fmt.Println("header encoded: ", hex.EncodeToString(buf))

	questions, err := EncodeQuestions(m.Questions)
	if err != nil {
		return []byte{}, err
	}
	fmt.Println("questions after beeing encoded: ", m.Questions[0], m.Questions[1])
	// fmt.Println("question: ", question)
	fmt.Println("questions encoded: ", hex.EncodeToString(questions))
	buf = append(buf, questions...)

	answers, err := EncodeAnswers(m.Answers, m.Questions)
	if err != nil {
		return []byte{}, err
	}
	fmt.Println("answers encoded: ", hex.EncodeToString(answers))
	// fmt.Println("answer: ", answer)
	// fmt.Println("answer encoded: ", hex.EncodeToString(answer))
	buf = append(buf, answers...)

	fmt.Println("full message: ", hex.EncodeToString(buf))
	return buf, nil
}
