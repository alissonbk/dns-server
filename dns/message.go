package dns

import (
	"encoding/hex"
	"fmt"
)

type Message struct {
	Header *Header
	// keeping the single ones just for testing
	Question  *Question
	Answer    *Answer
	Questions []Question
	Answers   []Answer
}

func DecodeMessage(payload []byte) (*Message, error) {
	message := &Message{}
	decodedHeader, err := DecodeHeader(payload)
	if err != nil {
		return message, err
	}
	message.Header = decodedHeader

	decodedQuestions, err := DecodeQuestions(payload, int(decodedHeader.QDCOUNT))
	if err != nil {
		return message, err
	}
	message.Questions = decodedQuestions

	// FIXME: handle multiple and fix start size from multiple questions
	decodedAnswers, err := DecodeAnswer(payload, decodedQuestions)
	if err != nil {
		return message, err
	}
	message.Answers = []Answer{*decodedAnswers}

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
	// fmt.Println("question: ", question)
	fmt.Println("questions encoded: ", hex.EncodeToString(questions))
	buf = append(buf, questions...)

	answers, err := EncodeAnswers(m.Answers, m.Questions)
	if err != nil {
		return []byte{}, err
	}
	// fmt.Println("answer: ", answer)
	// fmt.Println("answer encoded: ", hex.EncodeToString(answer))
	buf = append(buf, answers...)

	fmt.Println("full message: ", hex.EncodeToString(buf))
	return buf, nil
}
