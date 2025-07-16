package dns

import (
	"encoding/hex"
	"fmt"
)

type Message struct {
	Header   *Header
	Question *Question
	Answer   *Answer
}

func DecodeMessage(payload []byte) (*Message, error) {
	message := &Message{}
	decodedHeader, err := DecodeHeader(payload)
	if err != nil {
		return message, err
	}
	message.Header = decodedHeader

	decodedQuestion, err := DecodeQuestion(payload)
	if err != nil {
		return message, err
	}
	message.Question = decodedQuestion

	decodedAnswer, err := DecodeAnswer(payload, decodedQuestion.Size)
	if err != nil {
		return message, err
	}
	message.Answer = decodedAnswer

	return message, nil
}

func (m *Message) EncodeMessage() ([]byte, error) {
	buf, err := m.Header.EncodeHeader()
	if err != nil {
		return []byte{}, err
	}
	// fmt.Println("header: ", buf)
	// fmt.Println("header encoded: ", hex.EncodeToString(buf))

	question, err := m.Question.EncodeQuestion()
	if err != nil {
		return []byte{}, err
	}
	// fmt.Println("question: ", question)
	// fmt.Println("question encoded: ", hex.EncodeToString(question))
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
