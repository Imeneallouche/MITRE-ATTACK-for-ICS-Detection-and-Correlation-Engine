package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	gems "github.com/mitre/gems/src"
	"github.com/mitre/gems/src/gemsV14"
)

var (
	connectedToken = "TUlUUkUgQ2FsZGVyYShUTSkgZm9yIE9U"
	hiddenFlag1, _ = gemsV14.NewParameterBuilder().Name("flag1").String("REDACTED").Build()
	flag1, _       = gemsV14.NewParameterBuilder().Name("flag1").String("c4ot{parameter-flag}").Build()
	flag3, _       = gemsV14.NewParameterBuilder().Name("flag3").String("c4ot{directive-flag}").Build()

	channel0Name, _     = gemsV14.NewParameterBuilder().Name("ChannelName").String("Channel0").Build()
	channel0Id, _       = gemsV14.NewParameterBuilder().Name("ChannelID").Int(0).Build()
	channel0BitRates, _ = gemsV14.NewParameterBuilder().Name("BitRates").Int(200, 2000).Build()
	channel0, _         = gemsV14.NewParameterBuilder().Name("Channel0").Parameters(channel0Name, channel0Id, channel0BitRates).Build()

	channel1Name, _     = gemsV14.NewParameterBuilder().Name("ChannelName").String("Channel1").Build()
	channel1Id, _       = gemsV14.NewParameterBuilder().Name("ChannelID").Int(1).Build()
	channel1BitRates, _ = gemsV14.NewParameterBuilder().Name("BitRates").Int(400, 4000).Build()
	channel1, _         = gemsV14.NewParameterBuilder().Name("Channel1").Parameters(channel1Name, channel1Id, channel1BitRates).Build()

	channel2Name, _     = gemsV14.NewParameterBuilder().Name("ChannelName").String("Channel2").Build()
	channel2Id, _       = gemsV14.NewParameterBuilder().Name("ChannelID").Int(2).Build()
	channel2BitRates, _ = gemsV14.NewParameterBuilder().Name("BitRates").Int(600, 6000).Build()
	channel2, _         = gemsV14.NewParameterBuilder().Name("Channel2").Parameters(channel2Name, channel2Id, channel2BitRates).Build()
	channelList, _      = gemsV14.NewParameterBuilder().Name("ChannelList").Parameters(channel0, channel1, channel2).Build()

	directivesList, _ = gemsV14.NewParameterBuilder().Name("Directives").String("fetchFlag3").Build()
)

type demoServer struct {
	s          gems.Server
	configs    map[string][]gems.Parameter
	params     map[string]gems.Parameter
	directives map[string]gems.DirectiveFunction
}

func newDemoServer(psm string, addr string) *demoServer {
	demo := &demoServer{}

	switch psm {
	case "ascii":
		demo.s = gems.NewASCIIServer(addr, demo.Handler, gems.BodyFormatter{}, gemsV14.GemsV14{}, "")
	case "xml":
		demo.s = gems.NewXMLServer(addr, demo.Handler, gems.BodyFormatter{}, gemsV14.GemsV14{}, "")
	default:
		fmt.Printf("invalid psm '%s', must be 'ascii' or 'xml'\n", psm)
		os.Exit(1)
	}

	demo.configs = map[string][]gems.Parameter{
		"default":                  {channel0, channel1, channel2, channelList, hiddenFlag1, directivesList},
		"c4ot{configuration-flag}": {channel0, channel1, channel2, channelList, hiddenFlag1, directivesList},
		"secret":                   {channel0, channel1, channel2, channelList, flag1, directivesList},
	}
	demo.directives = map[string]gems.DirectiveFunction{
		"fetchFlag3": fetchFlag3,
	}
	demo.LoadConfig("default")
	return demo
}

func (s *demoServer) Handler(r gems.Message, v gems.Version) (gems.Response, error) {
	mb := v.NewMessageBuilder().Token(connectedToken).ResultCode(gems.ResultCodeSuccess)
	if r.TransactionID().Valid {
		mb.TransactionID(r.TransactionID().Int64)
	}
	if r.Version() != "1.4" {
		description := fmt.Sprintf("unsupported GEMS version '%s'", r.Version())
		msg, err := mb.ResultCode(gems.ResultCodeMalformedMessage).ResponseDescription(description).Build()
		resp, _ := msg.(gems.Response)
		return resp, err
	}

	switch r.Type() {
	case gems.LoadConfigMessageType:
		mb = mb.Type(gems.LoadConfigResponseType)

		msg, _ := r.(*gemsV14.LoadConfigMessage)
		loaded, err := s.LoadConfig(msg.ConfigName)
		if err != nil {
			mb = mb.ResultCode(gems.ResultCodeInvalidParameter).ResponseDescription(err.Error())
			break
		}
		mb.ParameterCount(loaded)

	case gems.GetConfigListMessageType:
		configs := make([]string, 0, len(s.configs))
		for name := range s.configs {
			configs = append(configs, name)
		}
		mb = mb.Type(gems.GetConfigListResponseType).ConfigurationList(configs)

	case gems.GetConfigMessageType:
		mb = mb.Type(gems.GetConfigResponseType)
		msg, _ := r.(*gemsV14.GetConfigMessage)
		p, result := s.GetConfig(msg.DesiredParameters)
		mb = mb.Result(result).Parameters(p...)

	case gems.SetConfigMessageType:
		msg, _ := r.(*gemsV14.SetConfigMessage)
		params := make([]gems.Parameter, len(msg.Parameters))
		for i := range len(msg.Parameters) {
			p, _ := msg.Parameters[i].(gems.Parameter)
			params[i] = p
		}
		set, result := s.SetConfig(params)
		mb = mb.Type(gems.SetConfigResponseType).ParameterCount(set).Result(result)

	case gems.SaveConfigMessageType:
		msg, _ := r.(*gemsV14.SaveConfigMessage)
		saved := s.SaveConfig(msg.ConfigName)
		mb = mb.Type(gems.SaveConfigResponseType).ParameterCount(saved)

	case gems.DirectiveMessageType:
		msg, _ := r.(*gemsV14.DirectiveMessage)
		params, result := s.CallDirective(msg.DirectiveName, msg.Arguments)
		mb = mb.Type(gems.DirectiveResponseType).Directive(msg.DirectiveName).Parameters(params...).Result(result)

	case gems.PingMessageType:
		mb = mb.Type(gems.PingResponseType)

	default:
		mb = mb.Type(gems.UnknownResponseType).ResultCode(gems.ResultCodeUnsupportedMessage)
	}

	msg, _ := mb.Build()
	resp, _ := msg.(gems.Response)
	return resp, nil
}

func (s *demoServer) LoadConfig(c string) (int, error) {
	params, found := s.configs[c]
	if !found {
		return 0, fmt.Errorf("unknown configuration name '%s'", c)
	}

	s.params = make(map[string]gems.Parameter)
	for _, p := range params {
		s.params[p.Name()] = p
	}
	return len(params), nil
}

func (s *demoServer) GetConfig(desired []string) ([]gems.Parameter, gems.Result) {
	var p []gems.Parameter

	switch len(desired) {
	case 0:
		p = make([]gems.Parameter, 0, len(s.params))
		for _, value := range s.params {
			p = append(p, value)
		}
	default:
		for _, name := range desired {
			value, found := s.params[name]
			if !found {
				result := gems.Result{Code: gems.ResultCodeInvalidParameter, Description: name}
				return []gems.Parameter{}, result
			}
			p = append(p, value)
		}
	}
	return p, gems.Result{Code: gems.ResultCodeSuccess}
}

func (s *demoServer) SetConfig(params []gems.Parameter) (int, gems.Result) {
	for _, p := range params {
		if _, found := s.params[p.Name()]; !found {
			result := gems.Result{Code: gems.ResultCodeInvalidParameter, Description: p.Name()}
			return 0, result
		}
	}

	for _, p := range params {
		s.params[p.Name()] = p
	}

	return len(params), gems.Result{Code: gems.ResultCodeSuccess}
}

func (s *demoServer) SaveConfig(name string) int {
	params := make([]gems.Parameter, 0, len(s.params))
	for _, p := range s.params {
		params = append(params, p)
	}

	s.configs[name] = params
	return len(params)
}

func (s *demoServer) CallDirective(name string, args *gemsV14.Arguments) ([]gems.Parameter, gems.Result) {
	var params []gems.Parameter
	f, found := s.directives[name]
	if !found {
		result := gems.Result{
			Code:        gems.ResultCodeInvalidParameter,
			Description: fmt.Sprintf("unknown directive '%s'", name),
		}
		return params, result
	}

	if args != nil {
		for _, p := range args.Parameters {
			param, _ := p.(gems.Parameter)
			params = append(params, param)
		}
	}
	return f(params)
}

func fetchFlag3([]gems.Parameter) ([]gems.Parameter, gems.Result) {
	result := gems.Result{Code: gems.ResultCodeSuccess}
	return []gems.Parameter{flag3}, result
}

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("usage: %s (xml|ascii) addr [--auth]\n", os.Args[0])
		os.Exit(1)
	}

	psm := os.Args[1]
	port := os.Args[2]

	server := newDemoServer(psm, port)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	server.s.Start()
	log.Printf("server listening at %s", server.s.Addr())

	<-ctx.Done()
	log.Println("shutting down the server")
	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.s.Close()
}
