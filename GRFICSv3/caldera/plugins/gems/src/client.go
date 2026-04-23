package gems

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mitre/gems/src/ascii"
)

var (
	clientTimeout = time.Second * 5
)

// Client is a GEMS client.
type Client struct {
	version Version
	model   platformSpecificModel
	f       MessageFormatter

	// GEMS Connection State
	token         string
	target        string
	transactionID int64
}

// NewClient creates a GEMS client of the specified Platform Specific Module (PSM).
// Valid values for psm are "XML" or "ASCII" (case-insensitive).
func NewClient(version Version, psm string, f MessageFormatter) (*Client, error) {
	c := &Client{f: f, transactionID: 0, version: version}
	switch strings.ToLower(psm) {
	case "xml":
		c.model = &xmlClient{}
	case "ascii":
		c.model = &asciiClient{}
	default:
		return nil, fmt.Errorf("unknown PSM '%s'", psm)
	}

	return c, nil
}

// Format uses the Client's MessageFormatter to format a GEMS Message.
func (c *Client) Format(msg Message) string {
	return c.f.Format(msg)
}

// ServerAddr returns the address of the connected server.
func (c *Client) ServerAddr() string {
	return c.model.ServerAddr()
}

// Connect sends a GEMS ConnectionRequestMessage to the specified address.
// The addr string should be formatted as in Go http package: "host:port".
// All ConnectionRequestMessages are required to specify a ConnectionType. token and target
// are both optional, if these arguments are a blank string ("") they will not be sent
// in the ConnectionRequestMessage.
func (c *Client) Connect(addr string, typ ConnectionType, token string, target string) error {
	return c.connect(false, addr, typ, token, target, false)
}

// ConnectTLS sends a GEMS ConnectionRequestMessage to the specified address, using a TLS
// connection.
// The addr string should be formatted as in Go http package: "host:port".
// If insecure is true, the connection will allow self-signed certificates.
// All ConnectionRequestMessages are required to specify a ConnectionType. token and target
// are both optional, if these arguments are a blank string ("") they will not be sent
// in the ConnectionRequestMessage.
func (c *Client) ConnectTLS(addr string, typ ConnectionType, token string, target string, insecure bool) error {
	return c.connect(true, addr, typ, token, target, insecure)
}

func (c *Client) connect(tls bool, addr string, typ ConnectionType, token string, target string, insecure bool) error {
	c.token = token
	c.target = target

	req, err := c.version.NewMessageBuilder().Type(ConnectMessageType).TransactionID(c.transactionID).Token(c.token).Target(c.target).ConnectionType(typ).Build()
	if err != nil {
		return err
	}

	var resp Response
	if tls {
		resp, err = c.model.ConnectTLS(addr, req, insecure, c.version)
	} else {
		resp, err = c.model.Connect(addr, req, c.version)
	}
	if err != nil {
		return err
	}

	c.token = resp.Token()
	c.transactionID++
	return err
}

// Disconnect sends a GEMS Disconnect message to gracefully close a connection.
func (c *Client) Disconnect(reason DisconnectReason) error {

	msg, err := c.version.NewMessageBuilder().Type(DisconnectMessageType).TransactionID(c.transactionID).
		Token(c.token).Target(c.target).DisconnectReason(reason).Build()
	if err != nil {
		return err
	}

	_, err = c.Send(msg)
	return err
}

// Send sends a pre-built GEMS Message.
// This is primarily for testing. Use the Client methods for
// each message type to build a message that uses information
// from the connection state.
func (c *Client) Send(m Message) (Response, error) {
	c.transactionID++
	return c.model.Send(m, c.version)
}

// GetConfig sends a GetConfigMessage to the connected GEMS
// device.
// Specific parameters may be requested by providing a list
// of parameter names. Leaving this list empty will request
// all parameters on the device.
func (c *Client) GetConfig(names ...string) (Response, error) {
	msg, err := c.version.NewMessageBuilder().Type(GetConfigMessageType).TransactionID(c.transactionID).
		Token(c.token).Target(c.target).DesiredParameters(names...).Build()
	if err != nil {
		return nil, err
	}
	return c.Send(msg)
}

// SetConfig sends a SetConfigMessage to the connected GEMS device.
func (c *Client) SetConfig(params []string) (Response, error) {
	mb := c.version.NewMessageBuilder().Type(SetConfigMessageType).TransactionID(c.transactionID).
		Token(c.token).Target(c.target)
	if params != nil {
		mb = mb.ASCIIParameters(params...)
	}

	msg, err := mb.Build()
	if err != nil {
		return nil, err
	}

	return c.Send(msg)
}

// SaveConfig sends a SaveConfigMessage to the connected GEMS device.
func (c *Client) SaveConfig(name string) (Response, error) {
	msg, err := c.version.NewMessageBuilder().Type(SaveConfigMessageType).TransactionID(c.transactionID).
		Token(c.token).Target(c.target).ConfigurationName(name).Build()
	if err != nil {
		return nil, err
	}

	return c.Send(msg)
}

// LoadConfig sends a LoadConfigMessage to the connected GEMS device.
func (c *Client) LoadConfig(name string) (Response, error) {
	msg, err := c.version.NewMessageBuilder().Type(LoadConfigMessageType).TransactionID(c.transactionID).
		Token(c.token).Target(c.target).ConfigurationName(name).Build()
	if err != nil {
		return nil, err
	}

	return c.Send(msg)
}

// GetConfigList sends a GetConfigListMessage to the connected GEMS device.
func (c *Client) GetConfigList() (Response, error) {
	msg, err := c.version.NewMessageBuilder().Type(GetConfigListMessageType).TransactionID(c.transactionID).
		Token(c.token).Target(c.target).Build()
	if err != nil {
		return nil, err
	}

	return c.Send(msg)
}

// Ping sends a PingMessage to the connected GEMS device.
func (c *Client) Ping() (Response, error) {
	msg, err := c.version.NewMessageBuilder().Type(PingMessageType).TransactionID(c.transactionID).
		Token(c.token).Target(c.target).Build()
	if err != nil {
		return nil, err
	}

	return c.Send(msg)
}

// Directive sends a DirectiveMessage to the connected GEMS device.
// DirectiveMessages require a directive name and optionally may contain
// a list of parameter arguments.
func (c *Client) Directive(dir string, params []string) (Response, error) {
	mb := c.version.NewMessageBuilder().Type(DirectiveMessageType).TransactionID(c.transactionID).
		Token(c.token).Target(c.target).Directive(dir)
	if params != nil {
		mb = mb.ASCIIParameters(params...)
	}

	msg, err := mb.Build()
	if err != nil {
		return nil, err
	}

	return c.Send(msg)
}

type platformSpecificModel interface {
	Connect(string, Message, Version) (Response, error)
	ConnectTLS(string, Message, bool, Version) (Response, error)
	Send(Message, Version) (Response, error)
	ServerAddr() string
}

type xmlClient struct {
	serverAddr string
	c          *http.Client
}

func (x xmlClient) ServerAddr() string {
	return x.serverAddr
}

func (x *xmlClient) Connect(addr string, req Message, v Version) (Response, error) {
	if !strings.HasPrefix(addr, "https://") && !strings.HasPrefix(addr, "http://") {
		addr = "http://" + addr
	}

	x.serverAddr = addr
	x.c = &http.Client{Timeout: clientTimeout}
	return x.Send(req, v)
}

func (x *xmlClient) ConnectTLS(addr string, req Message, insecure bool, v Version) (Response, error) {
	x.c = &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
			},
		},
	}
	if !strings.HasPrefix(addr, "https://") {
		addr = "https://" + addr
	}
	return x.Connect(addr, req, v)
}

func (x xmlClient) Send(m Message, v Version) (Response, error) {
	payload, err := xml.Marshal(m)
	if err != nil {
		return nil, err
	}

	requestBody := bytes.NewReader(payload)
	endpoint := fmt.Sprintf("%s/%s", x.serverAddr, m.Target())
	req, err := http.NewRequest("POST", endpoint, requestBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "OMG-GEMS")
	req.Header.Set("Content-Type", "text/xml")

	resp, err := x.c.Do(req)
	if err != nil {
		return nil, err
	}

	return x.Receive(resp, v)
}

func (x xmlClient) Receive(r *http.Response, v Version) (Response, error) {
	defer func(r io.ReadCloser) {
		_, _ = io.Copy(io.Discard, r)
		_ = r.Close()
	}(r.Body)

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("send failed: %s", r.Status)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	msg, err := ReceiveXMLMessage(body, v)
	if (err != nil) && (err != io.EOF) {
		return nil, err
	}

	resp, ok := msg.(Response)
	if !ok {
		return nil, fmt.Errorf("did not receive a response type message")
	}

	return resp, nil
}

type asciiClient struct {
	serverAddr string
	tls        *tls.Config
	conn       net.Conn
	dataCh     chan []byte
	errCh      chan error
}

func (a asciiClient) ServerAddr() string {
	return a.serverAddr
}

// Listen scans the connection for GEMS ASCII messages.
func (a asciiClient) Listen() {
	defer a.Close()

	scanner := bufio.NewScanner(a.conn)
	scanner.Split(ascii.SplitMessages)

	for scanner.Scan() {
		a.dataCh <- scanner.Bytes()
	}

	if err := scanner.Err(); err != nil {
		a.errCh <- err
	}
}

func (a *asciiClient) Connect(addr string, req Message, v Version) (Response, error) {
	a.serverAddr = addr
	a.dataCh = make(chan []byte)
	a.errCh = make(chan error)

	d := net.Dialer{Timeout: clientTimeout}
	conn, err := d.Dial("tcp", a.serverAddr)
	if err != nil {
		return nil, err
	}
	a.conn = conn

	go a.Listen()
	return a.Send(req, v)
}

func (a *asciiClient) ConnectTLS(addr string, req Message, insecure bool, v Version) (Response, error) {
	a.serverAddr = addr
	a.dataCh = make(chan []byte)
	a.errCh = make(chan error)
	a.tls = &tls.Config{InsecureSkipVerify: insecure}

	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: clientTimeout}, Config: a.tls}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	a.conn = conn

	go a.Listen()
	return a.Send(req, v)
}

func (a asciiClient) Send(m Message, v Version) (Response, error) {
	payload, err := ascii.Marshal(m)
	if err != nil {
		return nil, err
	}
	a.conn.Write(payload)
	return a.Receive(m.TransactionID(), v)
}

// Receive scans the connection stream for a ASCII message with a
// transaction ID matching the request. Any other messages are ignored.
func (a asciiClient) Receive(id NullInt64, v Version) (Response, error) {
	timeout := time.After(clientTimeout)
	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for response")
		case err := <-a.errCh:
			return nil, err
		case data := <-a.dataCh:
			msg, err := ReceiveASCIIMessage(data, v)
			if err != nil {
				continue
			}
			resp, ok := msg.(Response)
			if !ok {
				continue
			}
			if !resp.TransactionMatch(id) {
				continue
			}
			if resp.Result().Code != ResultCodeSuccess {
				return resp, fmt.Errorf("gems response: %s", resp.Result())
			}
			return resp, nil
		}
	}
}

func (a *asciiClient) Close() error {
	close(a.dataCh)
	close(a.errCh)
	return a.conn.Close()
}
