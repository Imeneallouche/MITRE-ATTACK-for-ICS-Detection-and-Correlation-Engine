package gems

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mitre/gems/src/ascii"
)

var (
	defaultToken = "TUlUUkUgQ2FsZGVyYShUTSkgZm9yIE9U"
)

type MessageHandler func(Message, Version) (Response, error)
type DirectiveFunction func([]Parameter) ([]Parameter, Result)

// DefaultMessageHandler responds to any incoming message with
// a successful UnknownResponse message.
func DefaultMessageHandler(r Message, v Version) (Response, error) {
	mb := v.NewMessageBuilder().Type(UnknownResponseType).Token(defaultToken)

	if r.TransactionID().Valid {
		mb.TransactionID(r.TransactionID().Int64)
	}

	msg, _ := mb.ResultCode(ResultCodeSuccess).Build()
	resp, _ := msg.(Response)
	return resp, nil
}

func connectionHandler(r Message, v Version, authToken string) (Response, error) {
	mb := v.NewMessageBuilder().Type(ConnectResponseType)
	if r.TransactionID().Valid {
		mb.TransactionID(r.TransactionID().Int64)
	}

	switch r.Type() {
	case ConnectMessageType:
		if (len(authToken) > 0) && (r.Token() != authToken) {
			msg, _ := mb.ResultCode(ResultCodeAccessDenied).ResponseDescription("Authentication failed.").Build()
			resp, _ := msg.(Response)
			return resp, fmt.Errorf("invalid access token")
		}
		msg, _ := mb.Token(defaultToken).ResultCode(ResultCodeSuccess).Build()
		resp, _ := msg.(Response)
		return resp, nil
	default:
		msg, _ := mb.Type(UnknownResponseType).ResultCode(ResultCodeInvalidState).ResponseDescription("Not connected").Build()
		resp, _ := msg.(Response)
		return resp, fmt.Errorf("invalid message type")
	}
}

func listen(addr string) (net.Listener, error) {
	switch addr {
	case "":
		return net.Listen("tcp", "127.0.0.1:0")
	default:
		return net.Listen("tcp", addr)
	}
}

type Server interface {
	Start()
	Close()
	Addr() string
}

type xmlServer struct {
	server    *http.Server
	listener  net.Listener
	address   string
	version   Version
	formatter MessageFormatter
	conns     map[string]struct{}
	authToken string
}

func NewXMLServer(addr string, handler MessageHandler, f MessageFormatter, v Version, authToken string) Server {
	l, err := listen(addr)
	if err != nil {
		log.Fatalf("failed to start Listener: %s", err)
	}

	s := xmlServer{
		listener:  l,
		formatter: f,
		server: &http.Server{
			Addr:              l.Addr().String(),
			ReadHeaderTimeout: time.Minute,
		},
		version:   v,
		authToken: authToken,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /", s.xmlHandlerWrapper(handler))
	s.server.Handler = drainMiddleware(mux)
	s.connectionWrapper()

	return &s
}

func messageFromRequest(r *http.Request, v Version) (Message, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	return ReceiveXMLMessage(body, v)
}

func drainMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		},
	)
}

func (s *xmlServer) xmlHandlerWrapper(handler MessageHandler) http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Printf("error: %s", err)
			}
		}()

		req, err := messageFromRequest(r, s.version)
		if err != nil {
			panic(err)
		}

		if req.Type() == DisconnectMessageType {
			log.Printf("%s disconnected", r.RemoteAddr)
			delete(s.conns, r.RemoteAddr)
			return
		}

		var resp Response
		switch _, ok := s.conns[r.RemoteAddr]; ok {
		case true:
			if resp, err = handler(req, s.version); err != nil {
				panic(err)
			}
		default:
			if resp, err = connectionHandler(req, s.version, s.authToken); err != nil {
				log.Printf("connection attempt by %s failed: %s", r.RemoteAddr, err)
				break
			}
			s.conns[r.RemoteAddr] = struct{}{}
		}

		out, err := xml.Marshal(resp)
		if err != nil {
			panic(err)
		}
		w.Write(out)
		s.Log(req, resp, r.RemoteAddr)
	}

	return fn
}

func (s *xmlServer) connectionWrapper() {
	s.server.ConnState = func(c net.Conn, cs http.ConnState) {
		switch cs {
		case http.StateNew:
			if s.conns == nil {
				s.conns = make(map[string]struct{})
			}
		case http.StateHijacked, http.StateClosed:
			delete(s.conns, c.RemoteAddr().String())
		}
	}
}

func (s *xmlServer) Log(req Message, resp Message, addr string) {
	var b strings.Builder

	var respCode ResultCode
	if m, ok := resp.(Response); ok {
		respCode = m.Result().Code
	}

	fmt.Fprintf(&b, "| %s | %s | %s | %s |", addr, req.Type(), resp.Type(), respCode)
	fmt.Fprintf(&b, "\n%s", s.formatter.Format(req))
	log.Println(b.String())
}

func (s xmlServer) Addr() string {
	return s.address
}

func (s *xmlServer) Start() {
	if s.address != "" {
		return
	}
	s.address = "http://" + s.listener.Addr().String()

	go func() {
		if err := s.server.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			log.Println(err)
		}
	}()
}

func (s *xmlServer) Close() {
	s.listener.Close()
	s.address = ""
}

type asciiServer struct {
	address   string
	listener  net.Listener
	handler   MessageHandler
	version   Version
	formatter MessageFormatter
	conns     map[string]struct{}
	authToken string

	wg         sync.WaitGroup
	shutdown   chan struct{}
	connection chan net.Conn
}

func NewASCIIServer(addr string, handler MessageHandler, f MessageFormatter, v Version, authToken string) Server {
	l, err := listen(addr)
	if err != nil {
		log.Fatalf("failed to start listener: %s", err)
	}

	return &asciiServer{
		listener:   l,
		handler:    handler,
		version:    v,
		formatter:  f,
		shutdown:   make(chan struct{}),
		connection: make(chan net.Conn),
		conns:      map[string]struct{}{},
		authToken:  authToken,
	}
}

func (s *asciiServer) Addr() string {
	return s.address
}

func (s *asciiServer) Start() {
	if s.address != "" {
		return
	}

	s.address = s.listener.Addr().String()
	s.wg.Add(2)
	go s.acceptConnections()
	go s.handleConnections()
}

func (s *asciiServer) acceptConnections() {
	defer s.wg.Done()

	go func() {
		for {
			select {
			case <-s.shutdown:
				return
			default:
				conn, err := s.listener.Accept()
				if err != nil {
					log.Println(err)
					continue
				}
				s.connection <- conn
			}
		}
	}()
}

func (s *asciiServer) handleConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.shutdown:
			return
		case conn := <-s.connection:
			go s.handlerWrapper(conn)
		}
	}
}

func (s *asciiServer) handlerWrapper(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	scanner := bufio.NewScanner(conn)
	scanner.Split(ascii.SplitMessages)
	for scanner.Scan() {
		req, err := ReceiveASCIIMessage(scanner.Bytes(), s.version)
		if err != nil {
			log.Printf("error: %s", err)
			continue
		}

		if req.Type() == DisconnectMessageType {
			log.Printf("%s disconnected", remoteAddr)
			delete(s.conns, remoteAddr)
			return
		}

		var resp Response
		switch _, ok := s.conns[remoteAddr]; ok {
		case true:
			if resp, err = s.handler(req, s.version); err != nil {
				log.Printf("error: %s", err)
				continue
			}
		default:
			if resp, err = connectionHandler(req, s.version, s.authToken); err != nil {
				log.Printf("connection attempt by %s failed: %s", remoteAddr, err)
				break
			}
			s.conns[remoteAddr] = struct{}{}
		}

		out, err := ascii.Marshal(resp)
		if err != nil {
			log.Printf("error: %s", err)
			continue
		}
		conn.Write(out)
		s.Log(req, resp, remoteAddr)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("scanner error: %s", err)
	}
}

func (s *asciiServer) Log(req Message, resp Message, addr string) {
	var b strings.Builder

	var respCode ResultCode
	if m, ok := resp.(Response); ok {
		respCode = m.Result().Code
	}

	fmt.Fprintf(&b, "| %s | %s | %s | %s |", addr, req.Type(), resp.Type(), respCode)
	fmt.Fprintf(&b, "\n%s", s.formatter.Format(req))
	log.Println(b.String())
}

func (s *asciiServer) Close() {
	close(s.shutdown)
	s.listener.Close()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return
	case <-time.After(time.Second):
		log.Printf("shutdown timed out")
		return
	}
}
