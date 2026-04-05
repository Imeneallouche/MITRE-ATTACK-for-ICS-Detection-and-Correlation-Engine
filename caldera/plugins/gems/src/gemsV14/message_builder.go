package gemsV14

import (
	"fmt"
	"time"

	gems "github.com/mitre/gems/src"
)

type MessageBuilder struct {
	typ           gems.MessageType
	header        MessageHeader
	result        gems.Result
	connType      gems.ConnectionType
	reason        gems.DisconnectReason
	configName    string
	configList    []string
	paramCount    int
	directiveName string
	params        []gems.XMLParameter
	desiredParams []string
}

func (GemsV14) NewMessageBuilder() gems.MessageBuilder {
	return &MessageBuilder{}
}

func (mb *MessageBuilder) Type(t gems.MessageType) gems.MessageBuilder {
	mb.typ = t
	return mb
}

func (mb *MessageBuilder) Target(s string) gems.MessageBuilder {
	mb.header.target = s
	return mb
}

func (mb *MessageBuilder) Timestamp(ts string) gems.MessageBuilder {
	t, _ := gems.TimeFromString(ts)
	mb.header.timestamp = t
	return mb
}

func (mb *MessageBuilder) TransactionID(id int64) gems.MessageBuilder {
	mb.header.transactionID = gems.NewNullInt64(id)
	return mb
}

func (mb *MessageBuilder) Token(t string) gems.MessageBuilder {
	mb.header.token = t
	return mb
}

// ConnectionType adds a Connection Type field to the message under construction.
// Used in a ConnectionRequestMessage.
func (mb *MessageBuilder) ConnectionType(t gems.ConnectionType) gems.MessageBuilder {
	mb.connType = t
	return mb
}

// DisconnectReason adds a Disconnect Reason field to the message under construction.
// Used in a DisconnectMessage.
func (mb *MessageBuilder) DisconnectReason(r gems.DisconnectReason) gems.MessageBuilder {
	mb.reason = r
	return mb
}

// ConfigurationName adds a Configuration Name field to the message under construction.
// Used in SaveConfigMessage and LoadConfigMessage.
func (mb *MessageBuilder) ConfigurationName(c string) gems.MessageBuilder {
	mb.configName = c
	return mb
}

// ConfigurationList adds a Configuration List field to the message under construction.
// Used in a GetConfigListResponse.
func (mb *MessageBuilder) ConfigurationList(lst []string) gems.MessageBuilder {
	mb.configList = lst
	return mb
}

// ParameterCount adds a Parameter Count field to the message under construction.
// Used in SetConfigResponse, SaveConfigResponse, and LoadConfigResponse.
func (mb *MessageBuilder) ParameterCount(c int) gems.MessageBuilder {
	mb.paramCount = c
	return mb
}

// Directive adds a Directive name field to the message under construction.
// Used in DirectiveMessage and DirectiveResponse.
func (mb *MessageBuilder) Directive(d string) gems.MessageBuilder {
	mb.directiveName = d
	return mb
}

// Parameters adds GEMS Parameters to the message under construction.
// Used in SetConfigMessage, GetConfigResponse, DirectiveMessage, and
// DirectiveResponse.
func (mb *MessageBuilder) Parameters(params ...gems.Parameter) gems.MessageBuilder {
	for _, p := range params {
		xmlParameter, ok := p.(gems.XMLParameter)
		if !ok {
			continue
		}
		mb.params = append(mb.params, xmlParameter)
	}
	return mb
}

// ASCIIParameters adds GEMS Parameters from ASCII formatted strings
// to the message under construction.
// Used in SetConfigMessage, GetConfigResponse, DirectiveMessage, and
// DirectiveResponse.
func (mb *MessageBuilder) ASCIIParameters(params ...string) gems.MessageBuilder {
	for _, s := range params {
		param, err := UnmarshalParameterASCII([]byte(s))
		if err != nil {
			continue
		}
		mb.params = append(mb.params, param)
	}
	return mb
}

// DesiredParameters adds GEMS Parameter names to the message under construction.
// Used in GetConfigMessage.
func (mb *MessageBuilder) DesiredParameters(params ...string) gems.MessageBuilder {
	mb.desiredParams = params
	return mb
}

// Result adds a GEMS Result Code and description to the message under construction.
func (mb *MessageBuilder) Result(r gems.Result) gems.MessageBuilder {
	mb.result.Code = r.Code
	mb.result.Description = r.Description
	return mb
}

// ResultCode adds a GEMS Result Code to the message under construction.
// Required in all Responses.
func (mb *MessageBuilder) ResultCode(c gems.ResultCode) gems.MessageBuilder {
	mb.result.Code = c
	return mb
}

// ResponseDescription adds a Response description to the message under construction.
// Optional in all Responses.
func (mb *MessageBuilder) ResponseDescription(d string) gems.MessageBuilder {
	mb.result.Description = d
	return mb
}

func (mb *MessageBuilder) Build() (gems.Message, error) {
	if mb.header.timestamp.IsZero() {
		mb.header.timestamp = gems.Time{Time: time.Now()}
	}

	var msg gems.Message
	switch mb.typ {
	case gems.UnknownResponseType:
		msg = newUnknownResponse(mb.header, mb.result)
	case gems.ConnectMessageType:
		msg = newConnectMessage(mb.header, mb.connType)
	case gems.ConnectResponseType:
		msg = newConnectResponse(mb.header, mb.result)
	case gems.DisconnectMessageType:
		msg = newDisconnectMessage(mb.header, mb.reason)
	case gems.PingMessageType:
		msg = newPingMessage(mb.header)
	case gems.PingResponseType:
		msg = newPingResponse(mb.header, mb.result)
	case gems.GetConfigMessageType:
		msg = newGetConfigMessage(mb.header, mb.desiredParams)
	case gems.GetConfigResponseType:
		msg = newGetConfigResponse(mb.header, mb.result, mb.params)
	case gems.SetConfigMessageType:
		msg = newSetConfigMessage(mb.header, mb.params)
	case gems.SetConfigResponseType:
		msg = newSetConfigResponse(mb.header, mb.result, mb.paramCount)
	case gems.GetConfigListMessageType:
		msg = newGetConfigListMessage(mb.header)
	case gems.GetConfigListResponseType:
		msg = newGetConfigListResponse(mb.header, mb.result, mb.configList)
	case gems.LoadConfigMessageType:
		msg = newLoadConfigMessage(mb.header, mb.configName)
	case gems.LoadConfigResponseType:
		msg = newLoadConfigResponse(mb.header, mb.result, mb.paramCount)
	case gems.SaveConfigMessageType:
		msg = newSaveConfigMessage(mb.header, mb.configName)
	case gems.SaveConfigResponseType:
		msg = newSaveConfigResponse(mb.header, mb.result, mb.paramCount)
	case gems.DirectiveMessageType:
		msg = newDirectiveMessage(mb.header, mb.directiveName, mb.params)
	case gems.DirectiveResponseType:
		msg = newDirectiveResponse(mb.header, mb.result, mb.directiveName, mb.params)
	case gems.AsyncStatusMessageType:
		msg = newAsyncStatusMessage(mb.header, mb.result, mb.params)
	default:
		return msg, fmt.Errorf("build not implemented for '%s'", mb.typ)
	}

	return msg, nil
}
