package gemsV14

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"

	gems "github.com/mitre/gems/src"
	"github.com/mitre/gems/src/ascii"
)

var (
	version      = "1.4"
	asciiVersion = "14"
	versionAttr  = xml.Attr{Name: xml.Name{Local: "gems_version"}, Value: version}
)

type GemsV14 struct{}

func (GemsV14) ReceiveASCIIMessage(data []byte, typ gems.MessageType) (gems.Message, error) {
	return receiveMessage(data, typ, ascii.Unmarshal)
}

func (GemsV14) ReceiveXMLMessage(data []byte, typ gems.MessageType) (gems.Message, error) {
	return receiveMessage(data, typ, xml.Unmarshal)
}

func newMessage(typ gems.MessageType) (gems.Message, error) {
	switch typ {
	case gems.UnknownResponseType:
		return &UnknownResponse{}, nil
	case gems.PingMessageType:
		return &PingMessage{}, nil
	case gems.PingResponseType:
		return &PingResponse{}, nil
	case gems.SetConfigMessageType:
		return &SetConfigMessage{}, nil
	case gems.SetConfigResponseType:
		return &SetConfigResponse{}, nil
	case gems.GetConfigMessageType:
		return &GetConfigMessage{}, nil
	case gems.GetConfigResponseType:
		return &GetConfigResponse{}, nil
	case gems.SaveConfigMessageType:
		return &SaveConfigMessage{}, nil
	case gems.SaveConfigResponseType:
		return &SaveConfigResponse{}, nil
	case gems.LoadConfigMessageType:
		return &LoadConfigMessage{}, nil
	case gems.LoadConfigResponseType:
		return &LoadConfigResponse{}, nil
	case gems.GetConfigListMessageType:
		return &GetConfigListMessage{}, nil
	case gems.GetConfigListResponseType:
		return &GetConfigListResponse{}, nil
	case gems.ConnectMessageType:
		return &ConnectMessage{}, nil
	case gems.ConnectResponseType:
		return &ConnectResponse{}, nil
	case gems.DisconnectMessageType:
		return &DisconnectMessage{}, nil
	case gems.DirectiveMessageType:
		return &DirectiveMessage{}, nil
	case gems.DirectiveResponseType:
		return &DirectiveResponse{}, nil
	case gems.AsyncStatusMessageType:
		return &AsyncStatusMessage{}, nil
	default:
		return nil, fmt.Errorf("unexpected type %s", typ)
	}
}

func receiveMessage(data []byte, typ gems.MessageType, unmarshalFunc func([]byte, any) error) (gems.Message, error) {
	msg, err := newMessage(typ)
	if err != nil {
		return msg, err
	}
	err = unmarshalFunc(data, &msg)
	return msg, err
}

type MessageHeader struct {
	target        string
	timestamp     gems.Time
	token         string
	transactionID gems.NullInt64
}

func (h MessageHeader) Version() string {
	return version
}

func (h MessageHeader) TransactionID() gems.NullInt64 {
	return h.transactionID
}

func (h MessageHeader) TransactionMatch(id gems.NullInt64) bool {
	if !id.Valid {
		return true
	}
	if !h.transactionID.Valid {
		return false
	}
	return h.transactionID.Int64 == id.Int64
}

func (h MessageHeader) Token() string {
	return h.token
}

func (h MessageHeader) Target() string {
	return h.target
}

func (h MessageHeader) AddXMLAttrs(start *xml.StartElement) error {
	start.Attr = append(start.Attr, versionAttr)
	if h.token != "" {
		tokenAttr := xml.Attr{Name: xml.Name{Local: "token"}, Value: h.token}
		start.Attr = append(start.Attr, tokenAttr)
	}

	if h.target != "" {
		targetAttr := xml.Attr{Name: xml.Name{Local: "target"}, Value: h.target}
		start.Attr = append(start.Attr, targetAttr)
	}

	if h.transactionID.Valid {
		idAttr, err := h.transactionID.MarshalXMLAttr(xml.Name{Local: "transaction_id"})
		if err != nil {
			return err
		}
		start.Attr = append(start.Attr, idAttr)
	}

	if !h.timestamp.IsZero() {
		timeAttr, err := h.timestamp.MarshalXMLAttr(xml.Name{Local: "timestamp"})
		if err != nil {
			return err
		}
		start.Attr = append(start.Attr, timeAttr)
	}

	return nil
}

func (h *MessageHeader) ExtractXMLAttrs(start xml.StartElement) error {
	for _, attr := range start.Attr {
		switch attr.Name.Local {
		case "gems_version":
			if attr.Value != version {
				return fmt.Errorf("incorrect gems version '%s'", attr.Value)
			}
		case "target":
			h.target = attr.Value
		case "token":
			h.token = attr.Value
		case "timestamp":
			t, err := gems.TimeFromString(attr.Value)
			if err != nil {
				return err
			}
			h.timestamp = t
		case "transaction_id":
			i, err := strconv.ParseInt(attr.Value, 10, 64)
			if err != nil {
				return err
			}
			h.transactionID = gems.NewNullInt64(i)
		}
	}

	return nil
}

func (h *MessageHeader) UnmarshalASCII(data []byte) error {
	if len(data) < 9 {
		return &ascii.UnmarshalError{Data: data, Msg: "incomplete GEMS-ASCII message"}
	}

	// Fixed length fields
	if !bytes.Equal(data[:5], []byte("|GEMS")) {
		return &ascii.UnmarshalError{Data: data[:5], Msg: "invalid start of message field"}
	}
	ver := string(data[6:8])
	if ver != asciiVersion {
		return fmt.Errorf("incorrect gems version '%s'", ver)
	}

	// Variable length fields
	fields := bytes.Split(data[9:], []byte{'|'})
	if len(fields) < 6 {
		return &ascii.UnmarshalError{Data: data, Msg: "incomplete GEMS-ASCII message"}
	}
	if !bytes.Equal(fields[len(fields)-1], []byte("END")) {
		return &ascii.UnmarshalError{Data: data, Msg: "missing message trailer"}
	}

	msgLen, err := strconv.ParseInt(string(fields[0]), 10, 64)
	if err != nil {
		return &ascii.UnmarshalError{Data: data, Msg: "invalid message length"}
	}
	if msgLen != int64(len(data)) {
		return &ascii.UnmarshalError{Data: data, Msg: "message length field does not match data length"}
	}

	if err := ascii.Unmarshal(fields[1], &h.transactionID); err != nil {
		return err
	}
	h.token = string(fields[2])
	if err := ascii.Unmarshal(fields[3], &h.timestamp); err != nil {
		return err
	}
	h.target = string(fields[4])

	return nil
}

type UnknownResponse struct {
	MessageHeader
	result gems.Result
}

func newUnknownResponse(h MessageHeader, r gems.Result) *UnknownResponse {
	return &UnknownResponse{
		MessageHeader: h,
		result:        r,
	}
}

func (m UnknownResponse) Type() gems.MessageType {
	return gems.UnknownResponseType
}

func (m UnknownResponse) Result() gems.Result {
	return m.result
}

func (m UnknownResponse) Body() map[string]any {
	body := m.result.Body()
	return body
}

func (m UnknownResponse) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.Encode(m.result)
	e.EncodeToken(start.End())
	return nil
}

func (m *UnknownResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "Result":
				d.DecodeElement(&m.result.Code, &se)
			case "description":
				d.DecodeElement(&m.result.Description, &se)
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m UnknownResponse) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|%s|", m.Type().ASCII(), m.result.Code, m.result.Description)
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *UnknownResponse) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 2)
	if err != nil {
		return err
	}
	m.result.Code = gems.ResultCode(content[0])
	m.result.Description = string(content[1])
	return nil
}

type ConnectMessage struct {
	MessageHeader
	ConnectionType gems.ConnectionType
}

func newConnectMessage(h MessageHeader, c gems.ConnectionType) *ConnectMessage {
	return &ConnectMessage{
		MessageHeader:  h,
		ConnectionType: c,
	}
}

func (m ConnectMessage) Type() gems.MessageType {
	return gems.ConnectMessageType
}

func (m ConnectMessage) Body() map[string]any {
	body := make(map[string]any)
	body["connection_type"] = string(m.ConnectionType)
	return body
}

func (m ConnectMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.EncodeElement(m.ConnectionType, xml.StartElement{Name: xml.Name{Local: "type"}})
	e.EncodeToken(start.End())
	return nil
}

func (m *ConnectMessage) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "type":
				d.DecodeElement(&m.ConnectionType, &se)
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m ConnectMessage) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|", m.Type().ASCII(), m.ConnectionType)
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *ConnectMessage) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 1)
	if err != nil {
		return err
	}
	m.ConnectionType = gems.ConnectionType(content[0])
	return nil
}

type ConnectResponse struct {
	MessageHeader
	result gems.Result
}

func newConnectResponse(h MessageHeader, r gems.Result) *ConnectResponse {
	return &ConnectResponse{
		MessageHeader: h,
		result:        r,
	}
}

func (m ConnectResponse) Type() gems.MessageType {
	return gems.ConnectResponseType
}

func (m ConnectResponse) Result() gems.Result {
	return m.result
}

func (m ConnectResponse) Body() map[string]any {
	body := m.result.Body()
	return body
}

func (m ConnectResponse) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.Encode(m.result)
	e.EncodeToken(start.End())
	return nil
}

func (m *ConnectResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "Result":
				d.DecodeElement(&m.result.Code, &se)
			case "description":
				d.DecodeElement(&m.result.Description, &se)
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m ConnectResponse) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|%s|", m.Type().ASCII(), m.result.Code, m.result.Description)
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *ConnectResponse) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 2)
	if err != nil {
		return err
	}
	m.result.Code = gems.ResultCode(content[0])
	m.result.Description = string(content[1])
	return nil
}

type DisconnectMessage struct {
	MessageHeader
	DisconnectReason gems.DisconnectReason
}

func newDisconnectMessage(h MessageHeader, r gems.DisconnectReason) *DisconnectMessage {
	return &DisconnectMessage{
		MessageHeader:    h,
		DisconnectReason: r,
	}
}

func (m DisconnectMessage) Type() gems.MessageType {
	return gems.DisconnectMessageType
}

func (m DisconnectMessage) Body() map[string]any {
	body := make(map[string]any)
	body["connection_type"] = string(m.DisconnectReason)
	return body
}

func (m DisconnectMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.EncodeElement(m.DisconnectReason, xml.StartElement{Name: xml.Name{Local: "reason"}})
	e.EncodeToken(start.End())
	return nil
}

func (m *DisconnectMessage) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "reason":
				d.DecodeElement(&m.DisconnectReason, &se)
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m DisconnectMessage) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|", m.Type().ASCII(), m.DisconnectReason)
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *DisconnectMessage) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 1)
	if err != nil {
		return err
	}
	m.DisconnectReason = gems.DisconnectReason(content[0])
	return nil
}

type PingMessage struct {
	MessageHeader
}

func newPingMessage(h MessageHeader) *PingMessage {
	return &PingMessage{MessageHeader: h}
}

func (m PingMessage) Type() gems.MessageType {
	return gems.PingMessageType
}

func (m PingMessage) Body() map[string]any {
	body := make(map[string]any, 0)
	return body
}

func (m PingMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.EncodeToken(start.End())
	return nil
}

func (m *PingMessage) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	err := m.ExtractXMLAttrs(start)
	d.Skip()
	return err
}

func (m PingMessage) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|", m.Type().ASCII())
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *PingMessage) UnmarshalASCII(data []byte) error {
	_, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 0)
	return err
}

type PingResponse struct {
	MessageHeader
	result gems.Result
}

func newPingResponse(h MessageHeader, r gems.Result) *PingResponse {
	return &PingResponse{
		MessageHeader: h,
		result:        r,
	}
}

func (m PingResponse) Type() gems.MessageType {
	return gems.PingResponseType
}

func (m PingResponse) Result() gems.Result {
	return m.result
}

func (m PingResponse) Body() map[string]any {
	body := m.result.Body()
	return body
}

func (m PingResponse) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.Encode(m.result)
	e.EncodeToken(start.End())
	return nil
}

func (m *PingResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "Result":
				d.DecodeElement(&m.result.Code, &se)
			case "description":
				d.DecodeElement(&m.result.Description, &se)
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m PingResponse) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|%s|", m.Type().ASCII(), m.result.Code, m.result.Description)
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *PingResponse) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 2)
	if err != nil {
		return err
	}
	m.result.Code = gems.ResultCode(content[0])
	m.result.Description = string(content[1])
	return nil
}

type GetConfigMessage struct {
	MessageHeader
	DesiredParameters []string
}

func newGetConfigMessage(h MessageHeader, params []string) *GetConfigMessage {
	return &GetConfigMessage{
		MessageHeader:     h,
		DesiredParameters: params,
	}
}

func (m GetConfigMessage) Type() gems.MessageType {
	return gems.GetConfigMessageType
}

func (m GetConfigMessage) Body() map[string]any {
	body := make(map[string]any, 1)
	parameters := make([]string, len(m.DesiredParameters))
	copy(parameters, m.DesiredParameters)
	body["desired_parameters"] = parameters
	return body
}

func (m GetConfigMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	for _, n := range m.DesiredParameters {
		parameterStart := xml.StartElement{Name: gems.ParameterType.XMLName()}
		nameAttr := xml.Attr{Name: xml.Name{Local: "name"}, Value: n}
		parameterStart.Attr = append(parameterStart.Attr, nameAttr)
		e.EncodeElement("", parameterStart)
	}
	e.EncodeToken(start.End())
	return nil
}

func (m *GetConfigMessage) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			var p gems.XMLParameter

			switch se.Name.Local {
			case "Parameter":
				p = newEmptyParameter()
			case "ParameterSet":
				p = newEmptyParameterSet()
			default:
				continue
			}
			if err := d.DecodeElement(&p, &se); err != nil {
				return err
			}
			m.DesiredParameters = append(m.DesiredParameters, p.Name())
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m GetConfigMessage) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|", m.Type().ASCII())

	paramCount := len(m.DesiredParameters)
	if paramCount == 0 {
		// Specification and examples are contradictory on how to format a request
		// for all parameters. This implementation follows the specification.
		content.WriteRune('|')
		return marshalASCIIMessage(b, m.MessageHeader, &content)
	}

	fmt.Fprintf(&content, "%d|", paramCount)
	for _, p := range m.DesiredParameters {
		content.SafeWrite(p)
		content.WriteRune('|')
	}
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *GetConfigMessage) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 1)
	if err != nil {
		return err
	}

	// Allow parameter count to be ''
	if bytes.Equal(content[0], nil) {
		return nil
	}

	paramCount, err := strconv.Atoi(string(content[0]))
	if (err != nil) || (paramCount != len(content)-1) {
		return &ascii.UnmarshalError{Data: content[0], Msg: "invalid number of parameters"}
	}

	m.DesiredParameters = make([]string, paramCount)
	for i := range paramCount {
		m.DesiredParameters[i] = unescape(string(content[i+1]))
	}
	return nil
}

type GetConfigResponse struct {
	MessageHeader
	result     gems.Result
	Parameters []gems.XMLParameter
}

func newGetConfigResponse(h MessageHeader, r gems.Result, params []gems.XMLParameter) *GetConfigResponse {
	return &GetConfigResponse{
		MessageHeader: h,
		result:        r,
		Parameters:    params,
	}
}

func (m GetConfigResponse) Type() gems.MessageType {
	return gems.GetConfigResponseType
}

func (m GetConfigResponse) Result() gems.Result {
	return m.result
}

func (m GetConfigResponse) Body() map[string]any {
	body := m.result.Body()
	parameters := make([]string, len(m.Parameters))
	for i, p := range m.Parameters {
		parameters[i] = p.String()
	}
	body["parameters"] = parameters
	return body
}

func (m GetConfigResponse) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.Encode(m.result)
	for _, p := range m.Parameters {
		e.Encode(p)
	}
	e.EncodeToken(start.End())
	return nil
}

func (m *GetConfigResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			var p gems.XMLParameter

			switch se.Name.Local {
			case "Result":
				d.DecodeElement(&m.result.Code, &se)
				continue
			case "description":
				d.DecodeElement(&m.result.Description, &se)
				continue
			case "Parameter":
				p = newEmptyParameter()
			case "ParameterSet":
				p = newEmptyParameterSet()
			default:
				continue
			}

			if err := d.DecodeElement(&p, &se); err != nil {
				return err
			}
			m.Parameters = append(m.Parameters, p)
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m GetConfigResponse) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|%s|", m.Type().ASCII(), m.result.Code, m.result.Description)

	paramCount := len(m.Parameters)
	fmt.Fprintf(&content, "%d|", paramCount)
	for _, param := range m.Parameters {
		param.MarshalASCII(&content)
		content.WriteRune('|')
	}
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *GetConfigResponse) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 3)
	if err != nil {
		return err
	}
	m.result.Code = gems.ResultCode(content[0])
	m.result.Description = string(content[1])

	m.Parameters, err = unmarshalParameterSliceASCII(content[2:])
	return err
}

type AsyncStatusMessage struct {
	MessageHeader
	result     gems.Result
	Parameters []gems.XMLParameter
}

func newAsyncStatusMessage(h MessageHeader, r gems.Result, params []gems.XMLParameter) *AsyncStatusMessage {
	return &AsyncStatusMessage{
		MessageHeader: h,
		result:        r,
		Parameters:    params,
	}
}

func (m AsyncStatusMessage) Type() gems.MessageType {
	return gems.AsyncStatusMessageType
}

func (m AsyncStatusMessage) Result() gems.Result {
	return m.result
}

func (m AsyncStatusMessage) Body() map[string]any {
	body := m.result.Body()
	parameters := make([]string, len(m.Parameters))
	for i, p := range m.Parameters {
		parameters[i] = p.String()
	}
	body["parameters"] = parameters
	return body
}

func (m AsyncStatusMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.Encode(m.result)
	for _, p := range m.Parameters {
		e.Encode(p)
	}
	e.EncodeToken(start.End())
	return nil
}

func (m *AsyncStatusMessage) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			var p gems.XMLParameter

			switch se.Name.Local {
			case "Result":
				d.DecodeElement(&m.result.Code, &se)
				continue
			case "description":
				d.DecodeElement(&m.result.Description, &se)
				continue
			case "Parameter":
				p = newEmptyParameter()
			case "ParameterSet":
				p = newEmptyParameterSet()
			default:
				continue
			}

			if err := d.DecodeElement(&p, &se); err != nil {
				return err
			}
			m.Parameters = append(m.Parameters, p)
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m AsyncStatusMessage) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|%s|", m.Type().ASCII(), m.result.Code, m.result.Description)

	paramCount := len(m.Parameters)
	fmt.Fprintf(&content, "%d|", paramCount)
	for _, param := range m.Parameters {
		param.MarshalASCII(&content)
		content.WriteRune('|')
	}
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *AsyncStatusMessage) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 3)
	if err != nil {
		return err
	}
	m.result.Code = gems.ResultCode(content[0])
	m.result.Description = string(content[1])

	m.Parameters, err = unmarshalParameterSliceASCII(content[2:])
	return err
}

type SetConfigMessage struct {
	MessageHeader
	Parameters []gems.XMLParameter
}

func newSetConfigMessage(h MessageHeader, params []gems.XMLParameter) *SetConfigMessage {
	return &SetConfigMessage{
		MessageHeader: h,
		Parameters:    params,
	}
}

func (m SetConfigMessage) Type() gems.MessageType {
	return gems.SetConfigMessageType
}

func (m SetConfigMessage) Body() map[string]any {
	body := make(map[string]any, 1)
	parameters := make([]string, len(m.Parameters))
	for i, p := range m.Parameters {
		parameters[i] = p.String()
	}
	body["parameters"] = parameters
	return body
}

func (m SetConfigMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	for _, p := range m.Parameters {
		e.Encode(p)
	}
	e.EncodeToken(start.End())
	return nil
}

func (m *SetConfigMessage) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			var p gems.XMLParameter

			switch se.Name.Local {
			case "Parameter":
				p = newEmptyParameter()
			case "ParameterSet":
				p = newEmptyParameterSet()
			default:
				continue
			}
			if err := d.DecodeElement(&p, &se); err != nil {
				return err
			}
			m.Parameters = append(m.Parameters, p)
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m SetConfigMessage) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|", m.Type().ASCII())

	paramCount := len(m.Parameters)
	if paramCount == 0 {
		return fmt.Errorf("cannot marshal empty SetConfigMessage")
	}
	fmt.Fprintf(&content, "%d|", paramCount)
	for _, param := range m.Parameters {
		param.MarshalASCII(&content)
		content.WriteRune('|')
	}
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *SetConfigMessage) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 1)
	if err != nil {
		return err
	}
	m.Parameters, err = unmarshalParameterSliceASCII(content)
	return err
}

type SetConfigResponse struct {
	MessageHeader
	result        gems.Result
	ParametersSet int
}

func newSetConfigResponse(h MessageHeader, r gems.Result, paramCount int) *SetConfigResponse {
	return &SetConfigResponse{
		MessageHeader: h,
		result:        r,
		ParametersSet: paramCount,
	}
}

func (m SetConfigResponse) Type() gems.MessageType {
	return gems.SetConfigResponseType
}

func (m SetConfigResponse) Result() gems.Result {
	return m.result
}

func (m SetConfigResponse) Body() map[string]any {
	body := m.result.Body()
	body["parameters_set"] = m.ParametersSet
	return body
}

func (m SetConfigResponse) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.Encode(m.result)
	e.EncodeElement(m.ParametersSet, xml.StartElement{Name: xml.Name{Local: "parameters_set"}})
	e.EncodeToken(start.End())
	return nil
}

func (m *SetConfigResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "Result":
				d.DecodeElement(&m.result.Code, &se)
				continue
			case "description":
				d.DecodeElement(&m.result.Description, &se)
				continue
			case "parameters_set":
				d.DecodeElement(&m.ParametersSet, &se)
			default:
				continue
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m SetConfigResponse) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|%s|%d|", m.Type().ASCII(), m.result.Code, m.result.Description, m.ParametersSet)
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *SetConfigResponse) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 3)
	if err != nil {
		return err
	}
	m.result.Code = gems.ResultCode(content[0])
	m.result.Description = string(content[1])
	m.ParametersSet, err = strconv.Atoi(string(content[2]))
	return err
}

type GetConfigListMessage struct {
	MessageHeader
}

func newGetConfigListMessage(h MessageHeader) *GetConfigListMessage {
	return &GetConfigListMessage{MessageHeader: h}
}

func (m GetConfigListMessage) Type() gems.MessageType {
	return gems.GetConfigListMessageType
}

func (m GetConfigListMessage) Body() map[string]any {
	body := make(map[string]any, 0)
	return body
}

func (m GetConfigListMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.EncodeToken(start.End())
	return nil
}

func (m *GetConfigListMessage) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	err := m.ExtractXMLAttrs(start)
	d.Skip()
	return err
}

func (m GetConfigListMessage) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|", m.Type().ASCII())
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *GetConfigListMessage) UnmarshalASCII(data []byte) error {
	_, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 0)
	return err
}

type GetConfigListResponse struct {
	MessageHeader
	result         gems.Result
	Configurations []string
}

func newGetConfigListResponse(h MessageHeader, r gems.Result, configs []string) *GetConfigListResponse {
	return &GetConfigListResponse{
		MessageHeader:  h,
		result:         r,
		Configurations: configs,
	}
}

func (m GetConfigListResponse) Type() gems.MessageType {
	return gems.GetConfigListResponseType
}

func (m GetConfigListResponse) Result() gems.Result {
	return m.result
}

func (m GetConfigListResponse) Body() map[string]any {
	body := m.result.Body()
	body["configurations"] = m.Configurations
	return body
}

func (m GetConfigListResponse) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.Encode(m.result)
	for _, c := range m.Configurations {
		e.EncodeElement(c, xml.StartElement{Name: xml.Name{Local: "ConfigurationName"}})
	}
	e.EncodeToken(start.End())
	return nil
}

func (m *GetConfigListResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "Result":
				d.DecodeElement(&m.result.Code, &se)
			case "description":
				d.DecodeElement(&m.result.Description, &se)
			case "ConfigurationName":
				var c string
				d.DecodeElement(&c, &se)
				m.Configurations = append(m.Configurations, c)
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m GetConfigListResponse) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|%s|", m.Type().ASCII(), m.result.Code, m.result.Description)

	configCount := len(m.Configurations)
	fmt.Fprintf(&content, "%d|", configCount)
	for _, config := range m.Configurations {
		content.SafeWrite(escape(config))
		content.WriteRune('|')
	}

	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *GetConfigListResponse) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 3)
	if err != nil {
		return err
	}
	m.result.Code = gems.ResultCode(content[0])
	m.result.Description = string(content[1])

	configCount, err := strconv.Atoi(string(content[2]))
	if (err != nil) || (configCount != len(content)-3) {
		return &ascii.UnmarshalError{Data: content[2], Msg: "invalid number of configurations"}
	}

	m.Configurations = make([]string, configCount)
	for i := range configCount {
		m.Configurations[i] = unescape(string(content[i+3]))
	}
	return nil
}

type LoadConfigMessage struct {
	MessageHeader
	ConfigName string
}

func newLoadConfigMessage(h MessageHeader, name string) *LoadConfigMessage {
	return &LoadConfigMessage{
		MessageHeader: h,
		ConfigName:    name,
	}
}

func (m LoadConfigMessage) Type() gems.MessageType {
	return gems.LoadConfigMessageType
}

func (m LoadConfigMessage) Body() map[string]any {
	body := map[string]any{"config_name": m.ConfigName}
	return body
}

func (m LoadConfigMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.EncodeElement(m.ConfigName, xml.StartElement{Name: xml.Name{Local: "name"}})
	e.EncodeToken(start.End())
	return nil
}

func (m *LoadConfigMessage) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "name":
				d.DecodeElement(&m.ConfigName, &se)
			default:
				continue
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m LoadConfigMessage) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|", m.Type().ASCII(), m.ConfigName)
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *LoadConfigMessage) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 1)
	if err != nil {
		return err
	}
	m.ConfigName = string(content[0])
	return nil
}

type LoadConfigResponse struct {
	MessageHeader
	result           gems.Result
	ParametersLoaded int
}

func newLoadConfigResponse(h MessageHeader, r gems.Result, paramCount int) *LoadConfigResponse {
	return &LoadConfigResponse{
		MessageHeader:    h,
		result:           r,
		ParametersLoaded: paramCount,
	}
}

func (m LoadConfigResponse) Type() gems.MessageType {
	return gems.LoadConfigResponseType
}

func (m LoadConfigResponse) Result() gems.Result {
	return m.result
}

func (m LoadConfigResponse) Body() map[string]any {
	body := m.result.Body()
	body["parameters_loaded"] = m.ParametersLoaded
	return body
}

func (m LoadConfigResponse) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.Encode(m.result)
	e.EncodeElement(m.ParametersLoaded, xml.StartElement{Name: xml.Name{Local: "parameters_loaded"}})
	e.EncodeToken(start.End())
	return nil
}

func (m *LoadConfigResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "Result":
				d.DecodeElement(&m.result.Code, &se)
				continue
			case "description":
				d.DecodeElement(&m.result.Description, &se)
				continue
			case "parameters_loaded":
				d.DecodeElement(&m.ParametersLoaded, &se)
			default:
				continue
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m LoadConfigResponse) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|%s|%d|", m.Type().ASCII(), m.result.Code, m.result.Description, m.ParametersLoaded)
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *LoadConfigResponse) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 3)
	if err != nil {
		return err
	}
	m.result.Code = gems.ResultCode(content[0])
	m.result.Description = string(content[1])
	m.ParametersLoaded, err = strconv.Atoi(string(content[2]))
	return err
}

type SaveConfigMessage struct {
	MessageHeader
	ConfigName string
}

func newSaveConfigMessage(h MessageHeader, name string) *SaveConfigMessage {
	return &SaveConfigMessage{
		MessageHeader: h,
		ConfigName:    name,
	}
}

func (m SaveConfigMessage) Type() gems.MessageType {
	return gems.SaveConfigMessageType
}

func (m SaveConfigMessage) Body() map[string]any {
	body := map[string]any{"config_name": m.ConfigName}
	return body
}

func (m SaveConfigMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.EncodeElement(m.ConfigName, xml.StartElement{Name: xml.Name{Local: "name"}})
	e.EncodeToken(start.End())
	return nil
}

func (m *SaveConfigMessage) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "name":
				d.DecodeElement(&m.ConfigName, &se)
			default:
				continue
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m SaveConfigMessage) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|", m.Type().ASCII(), m.ConfigName)
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *SaveConfigMessage) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 1)
	if err != nil {
		return err
	}
	m.ConfigName = string(content[0])
	return nil
}

type SaveConfigResponse struct {
	MessageHeader
	result          gems.Result
	ParametersSaved int
}

func newSaveConfigResponse(h MessageHeader, r gems.Result, paramCount int) *SaveConfigResponse {
	return &SaveConfigResponse{
		MessageHeader:   h,
		result:          r,
		ParametersSaved: paramCount,
	}
}

func (m SaveConfigResponse) Type() gems.MessageType {
	return gems.SaveConfigResponseType
}

func (m SaveConfigResponse) Result() gems.Result {
	return m.result
}

func (m SaveConfigResponse) Body() map[string]any {
	body := m.result.Body()
	body["parameters_saved"] = m.ParametersSaved
	return body
}

func (m SaveConfigResponse) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.Encode(m.result)
	e.EncodeElement(m.ParametersSaved, xml.StartElement{Name: xml.Name{Local: "parameters_saved"}})
	e.EncodeToken(start.End())
	return nil
}

func (m *SaveConfigResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "Result":
				d.DecodeElement(&m.result.Code, &se)
				continue
			case "description":
				d.DecodeElement(&m.result.Description, &se)
				continue
			case "parameters_saved":
				d.DecodeElement(&m.ParametersSaved, &se)
			default:
				continue
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m SaveConfigResponse) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|%s|%d|", m.Type().ASCII(), m.result.Code, m.result.Description, m.ParametersSaved)
	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *SaveConfigResponse) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 3)
	if err != nil {
		return err
	}
	m.result.Code = gems.ResultCode(content[0])
	m.result.Description = string(content[1])
	m.ParametersSaved, err = strconv.Atoi(string(content[2]))
	return err
}

type Arguments struct {
	Parameters []gems.XMLParameter
}

func newArguments(params []gems.XMLParameter) *Arguments {
	if len(params) == 0 {
		return nil
	}
	return &Arguments{
		Parameters: params,
	}
}

func (a Arguments) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	e.EncodeToken(start)
	for _, p := range a.Parameters {
		e.Encode(p)
	}
	e.EncodeToken(start.End())
	return nil
}

func (a *Arguments) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch se := t.(type) {
		case xml.StartElement:
			var p gems.XMLParameter

			switch se.Name.Local {
			case "Parameter":
				p = newEmptyParameter()
			case "ParameterSet":
				p = newEmptyParameterSet()
			default:
				continue
			}

			if err := d.DecodeElement(&p, &se); err != nil {
				return err
			}
			a.Parameters = append(a.Parameters, p)
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (a Arguments) MarshalASCII(b *ascii.Buffer) error {
	paramCount := len(a.Parameters)
	fmt.Fprintf(b, "%d|", paramCount)

	for _, param := range a.Parameters {
		param.MarshalASCII(b)
		b.WriteRune('|')
	}
	return nil
}

type DirectiveMessage struct {
	MessageHeader
	DirectiveName string
	Arguments     *Arguments
}

func newDirectiveMessage(h MessageHeader, name string, params []gems.XMLParameter) *DirectiveMessage {
	args := newArguments(params)
	return &DirectiveMessage{
		MessageHeader: h,
		DirectiveName: name,
		Arguments:     args,
	}
}

func (m DirectiveMessage) Type() gems.MessageType {
	return gems.DirectiveMessageType
}

func (m DirectiveMessage) Body() map[string]any {
	body := make(map[string]any, 2)
	body["directive_name"] = m.DirectiveName
	if m.Arguments == nil {
		body["arguments"] = []string{}
		return body
	}

	params := make([]string, len(m.Arguments.Parameters))
	for i, p := range m.Arguments.Parameters {
		params[i] = p.String()
	}
	body["arguments"] = params
	return body
}

func (m DirectiveMessage) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.EncodeElement(m.DirectiveName, xml.StartElement{Name: xml.Name{Local: "directive_name"}})
	e.EncodeElement(m.Arguments, xml.StartElement{Name: xml.Name{Local: "arguments"}})
	e.EncodeToken(start.End())
	return nil
}

func (m *DirectiveMessage) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "directive_name":
				d.DecodeElement(&m.DirectiveName, &se)
			case "arguments":
				m.Arguments = newArguments([]gems.XMLParameter{})
				d.DecodeElement(&m.Arguments, &se)
			default:
				continue
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m DirectiveMessage) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|", m.Type().ASCII())
	content.SafeWrite(m.DirectiveName)
	content.WriteRune('|')

	if m.Arguments == nil {
		content.WriteString("0|")
		return marshalASCIIMessage(b, m.MessageHeader, &content)
	}

	err := m.Arguments.MarshalASCII(&content)
	if err != nil {
		return err
	}

	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *DirectiveMessage) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 2)
	if err != nil {
		return err
	}
	m.DirectiveName = unescape(string(content[0]))
	params, err := unmarshalParameterSliceASCII(content[1:])
	if err != nil {
		return err
	}
	m.Arguments = newArguments(params)
	return nil
}

type DirectiveResponse struct {
	MessageHeader
	result        gems.Result
	DirectiveName string
	ReturnValues  *Arguments
}

func newDirectiveResponse(h MessageHeader, r gems.Result, name string, params []gems.XMLParameter) *DirectiveResponse {
	args := newArguments(params)
	return &DirectiveResponse{
		MessageHeader: h,
		result:        r,
		DirectiveName: name,
		ReturnValues:  args,
	}
}

func (m DirectiveResponse) Type() gems.MessageType {
	return gems.DirectiveResponseType
}

func (m DirectiveResponse) Result() gems.Result {
	return m.result
}

func (m DirectiveResponse) Body() map[string]any {
	body := m.result.Body()
	body["directive_name"] = m.DirectiveName
	if m.ReturnValues == nil {
		body["return_values"] = []string{}
		return body
	}

	params := make([]string, len(m.ReturnValues.Parameters))
	for i, p := range m.ReturnValues.Parameters {
		params[i] = p.String()
	}
	body["return_values"] = params
	return body
}

func (m DirectiveResponse) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = m.Type().XMLName()
	if err := m.AddXMLAttrs(&start); err != nil {
		return err
	}
	e.EncodeToken(start)
	e.Encode(m.result)
	e.EncodeElement(m.DirectiveName, xml.StartElement{Name: xml.Name{Local: "directive_name"}})
	e.EncodeElement(m.ReturnValues, xml.StartElement{Name: xml.Name{Local: "return_values"}})
	e.EncodeToken(start.End())
	return nil
}

func (m *DirectiveResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if err := m.ExtractXMLAttrs(start); err != nil {
		return err
	}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch se := t.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "directive_name":
				d.DecodeElement(&m.DirectiveName, &se)
			case "return_values":
				m.ReturnValues = newArguments([]gems.XMLParameter{})
				d.DecodeElement(&m.ReturnValues, &se)
			default:
				continue
			}
		case xml.EndElement:
			if se == start.End() {
				return nil
			}
		}
	}
}

func (m DirectiveResponse) MarshalASCII(b *ascii.Buffer) error {
	var content ascii.Buffer
	fmt.Fprintf(&content, "%s|%s|%s|", m.Type().ASCII(), m.result.Code, m.result.Description)
	content.SafeWrite(m.DirectiveName)
	content.WriteRune('|')

	if m.ReturnValues == nil {
		content.WriteString("0|")
		return marshalASCIIMessage(b, m.MessageHeader, &content)
	}

	err := m.ReturnValues.MarshalASCII(&content)
	if err != nil {
		return err
	}

	return marshalASCIIMessage(b, m.MessageHeader, &content)
}

func (m *DirectiveResponse) UnmarshalASCII(data []byte) error {
	content, err := unmarshalASCIIHeader(data, &m.MessageHeader, m.Type(), 4)
	if err != nil {
		return err
	}
	m.result.Code = gems.ResultCode(content[0])
	m.result.Description = string(content[1])
	m.DirectiveName = unescape(string(content[2]))
	params, err := unmarshalParameterSliceASCII(content[3:])
	if err != nil {
		return err
	}
	m.ReturnValues = newArguments(params)
	return nil
}
