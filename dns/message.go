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
	decodedAnswers, err := DecodeAnswer(payload, decodedQuestions[0].Size)
	if err != nil {
		return message, err
	}
	message.Answers = []Answer{*decodedAnswers}

	return message, nil
}

func (m *Message) EncodeMessage() ([]byte, error) {
	buf, err := m.Header.EncodeHeader()
	if err != nil {
		return []byte{}, err
	}
	// fmt.Println("header: ", buf)
	fmt.Println("header encoded: ", hex.EncodeToString(buf))

	question, err := m.Question.EncodeQuestion()
	if err != nil {
		return []byte{}, err
	}
	// fmt.Println("question: ", question)
	fmt.Println("question encoded: ", hex.EncodeToString(question))
	buf = append(buf, question...)

	answer, err := m.Answer.EncodeAnswer()
	if err != nil {
		return []byte{}, err
	}
	// fmt.Println("answer: ", answer)
	// fmt.Println("answer encoded: ", hex.EncodeToString(answer))
	buf = append(buf, answer...)

	fmt.Println("full message: ", hex.EncodeToString(buf))
	return buf, nil
}
