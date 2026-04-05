package gems

import (
	"bytes"
	"encoding/xml"
	"strconv"

	"github.com/mitre/gems/src/ascii"
)

type GenericMessage struct {
	XMLName       xml.Name
	Flavor        string    `xml:"-"`
	Version       string    `xml:"gems_version,attr"`
	Length        int64     `xml:"-"`
	TransactionID NullInt64 `xml:"transaction_id,attr"`
	Token         string    `xml:"token,attr"`
	Timestamp     Time      `xml:"timestamp,attr"`
	Target        string    `xml:"target,attr"`
	Fields        [][]byte  `xml:"-"`
}

func (m *GenericMessage) UnmarshalASCII(data []byte) error {
	if !bytes.HasPrefix(data, []byte("|")) {
		return &ascii.UnmarshalError{Data: data, Msg: "message missing standard header"}
	}
	data = bytes.TrimPrefix(data, []byte("|"))

	if !bytes.HasSuffix(data, []byte("|END")) {
		return &ascii.UnmarshalError{Data: data, Msg: "message missing standard trailer"}
	}
	data = bytes.TrimSuffix(data, []byte("|END"))

	splitData := bytes.Split(data, []byte("|"))
	if len(splitData) < 7 {
		return &ascii.UnmarshalError{Data: data, Msg: "message missing required fields"}
	}

	m.Flavor = string(splitData[0])
	m.Version = string(splitData[1])
	msgLen, err := strconv.ParseInt(string(splitData[2]), 10, 64)
	if err != nil {
		return &ascii.UnmarshalError{Data: splitData[2], Msg: "invalid message length"}
	}
	m.Length = msgLen
	if err := ascii.Unmarshal(splitData[3], &m.TransactionID); err != nil {
		return err
	}
	m.Token = string(splitData[4])

	switch m.Flavor {
	case "GEMS":
		if len(splitData) < 8 {
			return &ascii.UnmarshalError{Data: data, Msg: "message missing required fields"}
		}
		if err := ascii.Unmarshal(splitData[5], &m.Timestamp); err != nil {
			return err
		}
		m.Target = string(splitData[6])
		m.XMLName.Local = string(splitData[7])
		m.Fields = splitData[8:]
	default:
		m.Target = string(splitData[5])
		m.XMLName.Local = string(splitData[6])
		m.Fields = splitData[6:]
	}

	return nil
}

func (m GenericMessage) Type() MessageType {
	if m.XMLName.Space == "" {
		return MessageTypeFromASCII(m.XMLName.Local)
	}
	return MessageTypeFromXMLName(m.XMLName)
}

func ReceiveXMLMessage(data []byte, v Version) (Message, error) {
	var m GenericMessage
	err := xml.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}
	return v.ReceiveXMLMessage(data, m.Type())
}

func ReceiveASCIIMessage(data []byte, v Version) (Message, error) {
	var m GenericMessage
	if err := ascii.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return v.ReceiveASCIIMessage(data, m.Type())
}
