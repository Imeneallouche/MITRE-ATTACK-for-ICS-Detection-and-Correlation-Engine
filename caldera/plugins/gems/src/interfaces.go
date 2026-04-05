package gems

import (
	"encoding/xml"
	"fmt"

	"github.com/mitre/gems/src/ascii"
)

type Version interface {
	ReceiveASCIIMessage([]byte, MessageType) (Message, error)
	ReceiveXMLMessage([]byte, MessageType) (Message, error)
	NewMessageBuilder() MessageBuilder
}

type Message interface {
	Version() string
	TransactionID() NullInt64
	TransactionMatch(NullInt64) bool
	Token() string
	Target() string
	Type() MessageType
	Body() map[string]any
	ascii.Marshaler
	ascii.Unmarshaler
}

type XMLMessage interface {
	xml.Marshaler
	xml.Unmarshaler
	Message
}

type Response interface {
	Result() Result
	Message
}

type MessageBuilder interface {
	Type(MessageType) MessageBuilder
	Target(string) MessageBuilder
	Timestamp(string) MessageBuilder
	TransactionID(int64) MessageBuilder
	Token(string) MessageBuilder
	ConnectionType(ConnectionType) MessageBuilder
	DisconnectReason(DisconnectReason) MessageBuilder
	ConfigurationName(string) MessageBuilder
	ConfigurationList([]string) MessageBuilder
	ParameterCount(int) MessageBuilder
	Directive(string) MessageBuilder
	Parameters(...Parameter) MessageBuilder
	ASCIIParameters(...string) MessageBuilder
	DesiredParameters(...string) MessageBuilder
	Result(Result) MessageBuilder
	ResultCode(ResultCode) MessageBuilder
	ResponseDescription(string) MessageBuilder
	Build() (Message, error)
}

type Value interface {
	Type() Datatype
	fmt.Stringer
	ascii.Marshaler
	ascii.Unmarshaler
}

type XMLValue interface {
	xml.Marshaler
	xml.Unmarshaler
	Value
}

type Parameter interface {
	Value
	ValueType() Datatype
	Name() string
	Validate() error
}

type XMLParameter interface {
	XMLValue
	Parameter
}

type ParameterBuilder interface {
	Name(string) ParameterBuilder
	Multiplicity(int) ParameterBuilder
	String(...string) ParameterBuilder
	Boolean(...bool) ParameterBuilder
	Int(...int) ParameterBuilder
	Double(...float64) ParameterBuilder
	HexValue(...string) ParameterBuilder
	Time(...string) ParameterBuilder
	Build() (Parameter, error)
}
