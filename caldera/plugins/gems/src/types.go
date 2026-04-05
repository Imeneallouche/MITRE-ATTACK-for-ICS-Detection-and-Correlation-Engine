package gems

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mitre/gems/src/ascii"
)

const (
	Namespace   = "http://www.omg.org/spec/gems/20110323/basetypes"
	utimeLayout = "2006-__2T15:04:05.000000000Z"
)

type Result struct {
	Code        ResultCode
	Description string
}

func (r Result) Body() map[string]any {
	body := make(map[string]any)
	body["result_code"] = string(r.Code)
	if len(r.Description) > 0 {
		body["result_description"] = r.Description
	}
	return body
}

func (r Result) String() string {
	if r.Description == "" {
		return string(r.Code)
	}
	return fmt.Sprintf("%s, %s", r.Code, r.Description)
}

func (r Result) Error() string {
	return r.String()
}

func (r Result) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeElement(r.Code, xml.StartElement{Name: xml.Name{Local: "Result"}}); err != nil {
		return err
	}

	if r.Description != "" {
		if err := e.EncodeElement(r.Description, xml.StartElement{Name: xml.Name{Local: "description"}}); err != nil {
			return err
		}
	}
	return nil
}

type Time struct {
	time.Time
}

func TimeFromString(s string) (Time, error) {
	var (
		sec  int64
		nsec int64
		err  error
	)

	secStr, nsecStr, found := strings.Cut(s, ".")
	if found {
		if len(nsecStr) < 9 {
			nsecStr = fmt.Sprintf("%s%0*d", nsecStr, 9-len(nsecStr), 0)
		}
		if nsec, err = strconv.ParseInt(nsecStr, 10, 64); err != nil {
			return Time{}, err
		}
	}

	if sec, err = strconv.ParseInt(secStr, 10, 64); err != nil {
		return Time{}, err
	}

	t := time.Unix(sec, nsec)
	return Time{t}, nil
}

func TimeFromUtime(s string) (Time, error) {
	left, right, found := strings.Cut(s, ".")
	if !found {
		return Time{}, fmt.Errorf("Utime missing decimal seconds separator")
	}
	right, found = strings.CutSuffix(right, "Z")
	if !found {
		return Time{}, fmt.Errorf("Utime missing 'Z' time zone character")
	}
	right = fmt.Sprintf("%-9s", right)

	paddedTimeStr := fmt.Sprintf("%s.%sZ", left, right)
	paddedTimeStr = strings.ReplaceAll(paddedTimeStr, " ", "0")

	t, err := time.Parse(utimeLayout, paddedTimeStr)
	if err != nil {
		return Time{}, err
	}
	return Time{t}, nil
}

func (t *Time) UnmarshalXMLAttr(attr xml.Attr) error {
	parsed, err := TimeFromString(attr.Value)
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

func (t Time) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	s := t.FormatTime()
	s = strings.TrimRight(s, "0")
	return xml.Attr{Name: name, Value: s}, nil
}

func (t Time) String() string {
	sec := t.Unix()
	nsec := t.Sub(time.Unix(sec, 0)).Nanoseconds()
	return fmt.Sprintf("%d.%d", sec, nsec)
}

func (t Time) FormatTime() string {
	return t.String()
}

func (t Time) FormatUtime() string {
	return t.UTC().Format(utimeLayout)
}

func (t *Time) UnmarshalASCII(data []byte) error {
	var err error
	if *t, err = TimeFromString(string(data)); err != nil {
		return err
	}
	return nil
}

type NullInt64 struct {
	Int64 int64
	Valid bool
}

func NewNullInt64(i int64) NullInt64 {
	return NullInt64{i, true}
}

func (i *NullInt64) UnmarshalXMLAttr(attr xml.Attr) error {
	var err error
	i.Int64, err = strconv.ParseInt(attr.Value, 10, 64)
	if err != nil {
		i.Int64 = 0
		i.Valid = false
		return nil
	}
	i.Valid = true
	return nil
}

func (i NullInt64) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	if !i.Valid {
		return xml.Attr{}, nil
	}
	return xml.Attr{Name: name, Value: i.String()}, nil
}

func (i NullInt64) String() string {
	if !i.Valid {
		return ""
	}
	return strconv.FormatInt(i.Int64, 10)
}

func (i *NullInt64) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		i.Int64 = 0
		i.Valid = false
		return nil
	}

	val, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		i.Int64 = 0
		i.Valid = false
		return &ascii.UnmarshalError{Data: data, Msg: "invalid Transaction ID number"}
	}

	i.Int64 = val
	i.Valid = true
	return nil
}

type NullInt32 struct {
	Int32 int32
	Valid bool
}

func NewNullInt32(i int) NullInt32 {
	return NullInt32{int32(i), true}
}

func (i *NullInt32) UnmarshalXMLAttr(attr xml.Attr) error {
	i64, err := strconv.ParseInt(attr.Value, 10, 32)
	if err != nil {
		i.Int32 = 0
		i.Valid = false
		return nil
	}
	i.Int32 = int32(i64)
	i.Valid = true
	return nil
}

func (i NullInt32) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	if !i.Valid {
		return xml.Attr{}, nil
	}
	return xml.Attr{Name: name, Value: i.String()}, nil
}

func (i NullInt32) String() string {
	if !i.Valid {
		return ""
	}
	return strconv.FormatInt(int64(i.Int32), 10)
}

type MessageType int

const (
	UndefinedMessageType MessageType = iota

	MessageSequenceType

	SetConfigMessageType
	SetConfigResponseType

	GetConfigMessageType
	GetConfigResponseType

	GetConfigListMessageType
	GetConfigListResponseType

	LoadConfigMessageType
	LoadConfigResponseType

	SaveConfigMessageType
	SaveConfigResponseType

	DirectiveMessageType
	DirectiveResponseType

	PingMessageType
	PingResponseType

	ConnectMessageType
	ConnectResponseType

	DisconnectMessageType

	AsyncStatusMessageType

	UnknownResponseType
)

// XMLName returns the xml.Name for the GemsMessageType.
func (t MessageType) XMLName() xml.Name {
	return xml.Name{Space: Namespace, Local: t.String()}
}

func (t MessageType) String() string {
	switch t {
	case MessageSequenceType:
		return "MessageSequence"
	case SetConfigMessageType:
		return "SetConfigMessage"
	case SetConfigResponseType:
		return "SetConfigResponse"
	case GetConfigMessageType:
		return "GetConfigMessage"
	case GetConfigResponseType:
		return "GetConfigResponse"
	case GetConfigListMessageType:
		return "GetConfigListMessage"
	case GetConfigListResponseType:
		return "GetConfigListResponse"
	case LoadConfigMessageType:
		return "LoadConfigMessage"
	case LoadConfigResponseType:
		return "LoadConfigResponse"
	case SaveConfigMessageType:
		return "SaveConfigMessage"
	case SaveConfigResponseType:
		return "SaveConfigResponse"
	case DirectiveMessageType:
		return "DirectiveMessage"
	case DirectiveResponseType:
		return "DirectiveResponse"
	case PingMessageType:
		return "PingMessage"
	case PingResponseType:
		return "PingResponse"
	case ConnectMessageType:
		return "ConnectionRequestMessage"
	case ConnectResponseType:
		return "ConnectionRequestResponse"
	case DisconnectMessageType:
		return "DisconnectMessage"
	case AsyncStatusMessageType:
		return "AsyncStatusMessage"
	case UnknownResponseType:
		return "UnknownResponse"
	default:
		return "undefined"
	}
}

func (t MessageType) ASCII() string {
	switch t {
	case SetConfigMessageType:
		return "SET"
	case SetConfigResponseType:
		return "SET-R"
	case GetConfigMessageType:
		return "GET"
	case GetConfigResponseType:
		return "GET-R"
	case GetConfigListMessageType:
		return "GETL"
	case GetConfigListResponseType:
		return "GETL-R"
	case LoadConfigMessageType:
		return "LOAD"
	case LoadConfigResponseType:
		return "LOAD-R"
	case SaveConfigMessageType:
		return "SAVE"
	case SaveConfigResponseType:
		return "SAVE-R"
	case DirectiveMessageType:
		return "DIR"
	case DirectiveResponseType:
		return "DIR-R"
	case PingMessageType:
		return "PING"
	case PingResponseType:
		return "PING-R"
	case ConnectMessageType:
		return "CON"
	case ConnectResponseType:
		return "CON-R"
	case DisconnectMessageType:
		return "DISC"
	case AsyncStatusMessageType:
		return "ASYNC"
	case UnknownResponseType:
		return "UKN-R"
	default:
		return ""
	}
}

func MessageTypeFromASCII(t string) MessageType {
	switch t {
	case "SET":
		return SetConfigMessageType
	case "SET-R":
		return SetConfigResponseType
	case "GET":
		return GetConfigMessageType
	case "GET-R":
		return GetConfigResponseType
	case "GETL":
		return GetConfigListMessageType
	case "GETL-R":
		return GetConfigListResponseType
	case "LOAD":
		return LoadConfigMessageType
	case "LOAD-R":
		return LoadConfigResponseType
	case "SAVE":
		return SaveConfigMessageType
	case "SAVE-R":
		return SaveConfigResponseType
	case "DIR":
		return DirectiveMessageType
	case "DIR-R":
		return DirectiveResponseType
	case "PING":
		return PingMessageType
	case "PING-R":
		return PingResponseType
	case "CON":
		return ConnectMessageType
	case "CON-R":
		return ConnectResponseType
	case "DISC", "DIS":
		return DisconnectMessageType
	case "ASYNC":
		return AsyncStatusMessageType
	case "UKN-R", "ERR-R", "DIS-R":
		return UnknownResponseType
	default:
		return UndefinedMessageType
	}
}

func MessageTypeFromXMLName(n xml.Name) MessageType {
	switch n.Local {
	case "MessageSequence":
		return MessageSequenceType
	case "SetConfigMessage":
		return SetConfigMessageType
	case "SetConfigResponse":
		return SetConfigResponseType
	case "GetConfigMessage":
		return GetConfigMessageType
	case "GetConfigResponse":
		return GetConfigResponseType
	case "GetConfigListMessage":
		return GetConfigListMessageType
	case "GetConfigListResponse":
		return GetConfigListResponseType
	case "LoadConfigMessage":
		return LoadConfigMessageType
	case "LoadConfigResponse":
		return LoadConfigResponseType
	case "SaveConfigMessage":
		return SaveConfigMessageType
	case "SaveConfigResponse":
		return SaveConfigResponseType
	case "DirectiveMessage":
		return DirectiveMessageType
	case "DirectiveResponse":
		return DirectiveResponseType
	case "PingMessage":
		return PingMessageType
	case "PingResponse":
		return PingResponseType
	case "ConnectionRequestMessage":
		return ConnectMessageType
	case "ConnectionRequestResponse":
		return ConnectResponseType
	case "DisconnectMessage":
		return DisconnectMessageType
	case "AsyncStatusMessage":
		return AsyncStatusMessageType
	case "UnknownResponse":
		return UnknownResponseType
	default:
		return UndefinedMessageType
	}
}

type ResultCode string

const (
	ResultCodeSuccess              ResultCode = "SUCCESS"
	ResultCodeInvalidRange         ResultCode = "INVALID_RANGE"
	ResultCodeInvalidParameter     ResultCode = "INVALID_PARAMETER"
	ResultCodeInvalidState         ResultCode = "INVALID_STATE"
	ResultCodeInvalidVersion       ResultCode = "INVALID_VERSION"
	ResultCodeInvalidTarget        ResultCode = "INVALID_TARGET"
	ResultCodeConflictingParameter ResultCode = "CONFLICTING_PARAMETER"
	ResultCodeConflictingValues    ResultCode = "CONFLICTING_VALUES"
	ResultCodeUnsupportedMessage   ResultCode = "UNSUPPORTED_MESSAGE"
	ResultCodeMalformedMessage     ResultCode = "MALFORMED_MESSAGE"
	ResultCodeCommunicationError   ResultCode = "COMMUNICATION_ERROR"
	ResultCodeInternalError        ResultCode = "INTERNAL_ERROR"
	ResultCodeAccessDenied         ResultCode = "ACCESS_DENIED"
	ResultCodeOther                ResultCode = "OTHER"
)

type ConnectionType string

const (
	ConnectionTypeControlOnly      ConnectionType = "CONTROL_ONLY"
	ConnectionTypeStatusOnly       ConnectionType = "STATUS_ONLY"
	ConnectionTypeControlAndStatus ConnectionType = "CONTROL_AND_STATUS"
)

type DisconnectReason string

const (
	DisconnectReasonNormalTermination DisconnectReason = "NORMAL_TERMINATION"
	DisconnectReasonControlLost       DisconnectReason = "CONTROL_LOST"
	DisconnectReasonServiceTerminated DisconnectReason = "SERVICE_TERMINATED"
	DisconnectReasonOther             DisconnectReason = "OTHER"
)

type Datatype int

const (
	UndefinedType Datatype = iota
	StringType
	BooleanType
	ByteType
	UbyteType
	HexValueType
	DoubleType
	LongType
	UlongType
	IntType
	UintType
	ShortType
	UshortType
	TimeType
	UtimeType
	ParameterType
	ParameterSetType
)

// ASCIIName returns the ASCII name of the GEMS datatype.
func (t Datatype) ASCIIName() string {
	switch t {
	case StringType:
		return "string"
	case BooleanType:
		return "bool"
	case ByteType:
		return "byte"
	case UbyteType:
		return "ubyte"
	case HexValueType:
		return "hex_value"
	case DoubleType:
		return "double"
	case LongType:
		return "long"
	case UlongType:
		return "ulong"
	case IntType:
		return "int"
	case UintType:
		return "uint"
	case ShortType:
		return "short"
	case UshortType:
		return "ushort"
	case TimeType:
		return "time"
	case UtimeType:
		return "utime"
	case ParameterSetType:
		return "set_type"
	default:
		return "undefined"
	}
}

// String returns the name of the Gems datatype in XML format.
func (t Datatype) String() string {
	switch t {
	case StringType:
		return "string"
	case BooleanType:
		return "boolean"
	case ByteType:
		return "byte"
	case UbyteType:
		return "ubyte"
	case HexValueType:
		return "hex_value"
	case DoubleType:
		return "double"
	case LongType:
		return "long"
	case UlongType:
		return "ulong"
	case IntType:
		return "int"
	case UintType:
		return "uint"
	case ShortType:
		return "short"
	case UshortType:
		return "ushort"
	case TimeType:
		return "time"
	case UtimeType:
		return "utime"
	case ParameterType:
		return "Parameter"
	case ParameterSetType:
		return "ParameterSet"
	default:
		return "undefined"
	}
}

// XMLName returns the xml.Name for the Gems datatype.
func (t Datatype) XMLName() xml.Name {
	return xml.Name{Space: Namespace, Local: t.String()}
}

// MarshalXMLAttr implements xml.MarshalerAttr
func (t Datatype) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	return xml.Attr{Name: name, Value: t.XMLName().Local}, nil
}

// UnmarshalXMLAttr implements xml.UnmarshalerAttr
func (t *Datatype) UnmarshalXMLAttr(attr xml.Attr) error {
	*t = DatatypeFromXML(attr.Value)
	return nil
}

// DatatypeFromASCII returns the Gems datatype matching
// an ASCII formatted type string.
func DatatypeFromASCII(typ string) Datatype {
	switch typ {
	case "string":
		return StringType
	case "bool", "boolean":
		return BooleanType
	case "byte":
		return ByteType
	case "ubyte":
		return UbyteType
	case "hex_value":
		return HexValueType
	case "double":
		return DoubleType
	case "long", "int64":
		return LongType
	case "ulong":
		return UlongType
	case "int":
		return IntType
	case "uint":
		return UintType
	case "short":
		return ShortType
	case "ushort":
		return UshortType
	case "time":
		return TimeType
	case "utime":
		return UtimeType
	case "set_type":
		return ParameterSetType
	default:
		return UndefinedType
	}
}

// DatatypeFromXML returns the Gems datatype matching
// an XML formatted type string.
func DatatypeFromXML(t string) Datatype {
	switch t {
	case "string":
		return StringType
	case "boolean":
		return BooleanType
	case "byte":
		return ByteType
	case "ubyte":
		return UbyteType
	case "hex_value":
		return HexValueType
	case "double":
		return DoubleType
	case "long":
		return LongType
	case "ulong":
		return UlongType
	case "int":
		return IntType
	case "uint":
		return UintType
	case "short":
		return ShortType
	case "ushort":
		return UshortType
	case "time":
		return TimeType
	case "utime":
		return UtimeType
	case "Parameter":
		return ParameterType
	case "ParameterSet":
		return ParameterSetType
	default:
		return UndefinedType
	}
}
