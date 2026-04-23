package gemsV14_test

import (
	"encoding/xml"
	"fmt"
	"reflect"
	"strings"
	"testing"

	gems "github.com/mitre/gems/src"
	"github.com/mitre/gems/src/ascii"
	"github.com/mitre/gems/src/gemsV14"
)

var (
	v            = gemsV14.GemsV14{}
	target       = "System/Device1"
	id     int64 = 1

	connectMessage, _         = v.NewMessageBuilder().Type(gems.ConnectMessageType).Target(target).Timestamp("1410819035.26").TransactionID(id).ConnectionType(gems.ConnectionTypeControlAndStatus).Build()
	connectResponseFailure, _ = v.NewMessageBuilder().Type(gems.ConnectResponseType).Target(target).Timestamp("1410819035.26").TransactionID(id).ResultCode(gems.ResultCodeInvalidTarget).ResponseDescription("Target System/Device1 does not exist in this system").Build()
	connectResponseSuccess, _ = v.NewMessageBuilder().Type(gems.ConnectResponseType).Target(target).Timestamp("1410819035.26").TransactionID(id).ResultCode(gems.ResultCodeSuccess).Build()

	iterations, _       = gemsV14.NewParameterBuilder().Name("Iterations").Int(2000).Build()
	title, _            = gemsV14.NewParameterBuilder().Name("Title").String("Run 1").Build()
	directiveMessage, _ = v.NewMessageBuilder().Type(gems.DirectiveMessageType).Target(target).Timestamp("1410819035.27").TransactionID(id).Directive("StartProcessing").Parameters(iterations, title).Build()

	results, _           = gemsV14.NewParameterBuilder().Name("Results").Int(12, 47, 33).Build()
	directiveResponse, _ = v.NewMessageBuilder().Type(gems.DirectiveResponseType).Target(target).Timestamp("1410819035.27").TransactionID(id).Directive("StartProcessing").Parameters(results).Build()

	disconnect, _            = v.NewMessageBuilder().Type(gems.DisconnectMessageType).Target(target).Timestamp("1410819035.27").TransactionID(id).Directive("StartProcessing").DisconnectReason(gems.DisconnectReasonNormalTermination).Build()
	getConfigListMessage, _  = v.NewMessageBuilder().Type(gems.GetConfigListMessageType).Target(target).Timestamp("1410819035.28").TransactionID(id).Build()
	getConfigListResponse, _ = v.NewMessageBuilder().Type(gems.GetConfigListResponseType).Target(target).Timestamp("1410819035.28").TransactionID(id).ResultCode(gems.ResultCodeSuccess).ConfigurationList([]string{"ConfigA", "ConfigB", "ConfigC"}).Build()
	getConfigMessageAll, _   = v.NewMessageBuilder().Type(gems.GetConfigMessageType).Target(target).Timestamp("1410819035.28").TransactionID(id).Build()

	getConfigMessageParameterized, _ = v.NewMessageBuilder().Type(gems.GetConfigMessageType).Target(target).Timestamp("1410819035.28").TransactionID(id).DesiredParameters("PacketLength", "FillPacket", "ChannelConfigList").Build()

	packetLength, _      = gemsV14.NewParameterBuilder().Name("PacketLength").Int(1024).Build()
	fillPacket, _        = gemsV14.NewParameterBuilder().Name("FillPacket").Boolean(true).Build()
	channel0BitRate, _   = gemsV14.NewParameterBuilder().Name("BitRate").Int(200000).Build()
	channelConfig0, _    = gemsV14.NewParameterBuilder().Name("Channel0").Parameters(channel0Name, channel0Id, channel0BitRate).Build()
	channel1BitRate, _   = gemsV14.NewParameterBuilder().Name("BitRate").Int(400000).Build()
	channelConfig1, _    = gemsV14.NewParameterBuilder().Name("Channel1").Parameters(channel1Name, channel1Id, channel1BitRate).Build()
	channel2BitRate, _   = gemsV14.NewParameterBuilder().Name("BitRate").Int(600000).Build()
	channelConfig2, _    = gemsV14.NewParameterBuilder().Name("Channel2").Parameters(channel2Name, channel2Id, channel2BitRate).Build()
	channelConfigList, _ = gemsV14.NewParameterBuilder().Name("ChannelConfigList").Parameters(channelConfig0, channelConfig1, channelConfig2).Build()
	getConfigResponse, _ = v.NewMessageBuilder().Type(gems.GetConfigResponseType).Target(target).Timestamp("1410819035.28").TransactionID(id).Parameters(packetLength, fillPacket, emptyStringList, emptyIntList, channelConfigList).Build()

	loadConfigMessage, _  = v.NewMessageBuilder().Type(gems.LoadConfigMessageType).Target(target).Timestamp("1410819035.28").TransactionID(id).ConfigurationName("MySavedConfig").Build()
	loadConfigResponse, _ = v.NewMessageBuilder().Type(gems.LoadConfigResponseType).Target(target).Timestamp("1410819035.28").TransactionID(id).ResultCode(gems.ResultCodeSuccess).ParameterCount(14).Build()

	pingMessage, _  = v.NewMessageBuilder().Type(gems.PingMessageType).Target(target).Timestamp("1410819035.28").TransactionID(id).Build()
	pingResponse, _ = v.NewMessageBuilder().Type(gems.PingResponseType).Target(target).Timestamp("1410819035.28").TransactionID(id).ResultCode(gems.ResultCodeSuccess).Build()

	saveConfigMessage, _  = v.NewMessageBuilder().Type(gems.SaveConfigMessageType).Target(target).Timestamp("1410819035.28").TransactionID(id).ConfigurationName("MySavedConfig").Build()
	saveConfigResponse, _ = v.NewMessageBuilder().Type(gems.SaveConfigResponseType).Target(target).Timestamp("1410819035.28").TransactionID(id).ResultCode(gems.ResultCodeSuccess).ParameterCount(27).Build()

	setConfigMessageTypes, _  = v.NewMessageBuilder().Type(gems.SetConfigMessageType).Target(target).Timestamp("1410819035.27").TransactionID(id).Parameters(intValue, hexValue, boolValue, doubleValue, longValue, timeValue, utimeValue, stringValue, emptyStringValue, intList, hexList, boolList, doubleList, longList, timeList, utimeList, stringList, emptyStringList, singleParameterSet, parameterSetList).Build()
	setConfigResponse, _      = v.NewMessageBuilder().Type(gems.SetConfigResponseType).Target(target).Timestamp("1410819035.28").TransactionID(id).ParameterCount(5).ResultCode(gems.ResultCodeSuccess).Build()
	ampersand, _              = gemsV14.NewParameterBuilder().Name("Ampersand").String("Bob & Sally").Build()
	pipe, _                   = gemsV14.NewParameterBuilder().Name("Pipe").String("Bob | Sally").Build()
	comma, _                  = gemsV14.NewParameterBuilder().Name("Comma").String("Bob, Sally").Build()
	semicolon, _              = gemsV14.NewParameterBuilder().Name("Semicolon").String("Bob; Sally").Build()
	lessThan, _               = gemsV14.NewParameterBuilder().Name("LessThan").String("Bob < Sally").Build()
	setConfigMessageEscape, _ = v.NewMessageBuilder().Type(gems.SetConfigMessageType).Target(target).Timestamp("1410819035.27").TransactionID(id).Parameters(ampersand, pipe, comma, semicolon, lessThan).Build()

	unknownResponse, _ = v.NewMessageBuilder().Type(gems.UnknownResponseType).Timestamp("1410819035.26").TransactionID(int64(0)).ResultCode(gems.ResultCodeMalformedMessage).ResponseDescription("Not a GEMS message").Build()
)

var messageMarshalTests = []struct {
	Value          gems.Message
	ExpectASCII    string
	ExpectXML      string
	MarshalOnly    bool
	MarshalError   string
	UnmarshalOnly  bool
	UnmarshalError string
}{
	{Value: connectMessage, ExpectASCII: "|GEMS|14|0000000085|1||1410819035.260000000|System/Device1|CON|CONTROL_AND_STATUS|END", ExpectXML: `<ConnectionRequestMessage xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.26"><type>CONTROL_AND_STATUS</type></ConnectionRequestMessage>`},
	{Value: connectResponseFailure, ExpectASCII: "|GEMS|14|0000000135|1||1410819035.260000000|System/Device1|CON-R|INVALID_TARGET|Target System/Device1 does not exist in this system|END", ExpectXML: `<ConnectionRequestResponse xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.26"><Result>INVALID_TARGET</Result><description>Target System/Device1 does not exist in this system</description></ConnectionRequestResponse>`},
	{Value: connectResponseSuccess, ExpectASCII: "|GEMS|14|0000000077|1||1410819035.260000000|System/Device1|CON-R|SUCCESS||END", ExpectXML: `<ConnectionRequestResponse xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.26"><Result>SUCCESS</Result></ConnectionRequestResponse>`},
	{Value: directiveMessage, ExpectASCII: "|GEMS|14|0000000123|1||1410819035.270000000|System/Device1|DIR|StartProcessing|2|Iterations:int=2000|Title:string=Run 1|END", ExpectXML: `<DirectiveMessage xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.27"><directive_name>StartProcessing</directive_name><arguments><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="Iterations"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2000</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="Title"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Run 1</string></Parameter></arguments></DirectiveMessage>`},
	{Value: directiveResponse, ExpectASCII: "|GEMS|14|0000000112|1||1410819035.270000000|System/Device1|DIR-R|||StartProcessing|1|Results:int[3]=12,47,33|END", ExpectXML: `<DirectiveResponse xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.27"><Result></Result><directive_name>StartProcessing</directive_name><return_values><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="Results" multiplicity="3"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">12</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">47</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">33</int></Parameter></return_values></DirectiveResponse>`},
	{Value: disconnect, ExpectASCII: "|GEMS|14|0000000086|1||1410819035.270000000|System/Device1|DISC|NORMAL_TERMINATION|END", ExpectXML: `<DisconnectMessage xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.27"><reason>NORMAL_TERMINATION</reason></DisconnectMessage>`},
	{Value: getConfigListMessage, ExpectASCII: "|GEMS|14|0000000067|1||1410819035.280000000|System/Device1|GETL|END", ExpectXML: `<GetConfigListMessage xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"></GetConfigListMessage>`},
	{Value: getConfigListResponse, ExpectASCII: "|GEMS|14|0000000104|1||1410819035.280000000|System/Device1|GETL-R|SUCCESS||3|ConfigA|ConfigB|ConfigC|END", ExpectXML: `<GetConfigListResponse xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"><Result>SUCCESS</Result><ConfigurationName>ConfigA</ConfigurationName><ConfigurationName>ConfigB</ConfigurationName><ConfigurationName>ConfigC</ConfigurationName></GetConfigListResponse>`},
	{Value: getConfigMessageAll, ExpectASCII: "|GEMS|14|0000000067|1||1410819035.280000000|System/Device1|GET||END", ExpectXML: `<GetConfigMessage xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"></GetConfigMessage>`},
	{Value: getConfigMessageParameterized, ExpectASCII: "|GEMS|14|0000000110|1||1410819035.280000000|System/Device1|GET|3|PacketLength|FillPacket|ChannelConfigList|END", ExpectXML: `<GetConfigMessage xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="PacketLength"></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="FillPacket"></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelConfigList"></Parameter></GetConfigMessage>`},
	{Value: getConfigResponse, ExpectASCII: "|GEMS|14|0000000385|1||1410819035.280000000|System/Device1|GET-R|||5|PacketLength:int=1024|FillPacket:bool=true|EmptyStringList:string[0]=|EmptyIntList:int[0]=|ChannelConfigList:set_type[3]=ChannelName:string=Channel0;ChannelID:int=0;BitRate:int=200000;,ChannelName:string=Channel1;ChannelID:int=1;BitRate:int=400000;,ChannelName:string=Channel2;ChannelID:int=2;BitRate:int=600000;|END", ExpectXML: `<GetConfigResponse xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"><Result></Result><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="PacketLength"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1024</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="FillPacket"><boolean xmlns="http://www.omg.org/spec/gems/20110323/basetypes">true</boolean></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="EmptyStringList" multiplicity="0"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes"></string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="EmptyIntList" multiplicity="0"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes"></int></Parameter><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelConfigList" multiplicity="3"><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelName"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Channel0</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelID"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">0</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BitRate"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">200000</int></Parameter></ParameterSet><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelName"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Channel1</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelID"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BitRate"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">400000</int></Parameter></ParameterSet><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelName"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Channel2</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelID"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BitRate"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">600000</int></Parameter></ParameterSet></ParameterSet></GetConfigResponse>`},
	{Value: loadConfigMessage, ExpectASCII: "|GEMS|14|0000000081|1||1410819035.280000000|System/Device1|LOAD|MySavedConfig|END", ExpectXML: `<LoadConfigMessage xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"><name>MySavedConfig</name></LoadConfigMessage>`},
	{Value: loadConfigResponse, ExpectASCII: "|GEMS|14|0000000081|1||1410819035.280000000|System/Device1|LOAD-R|SUCCESS||14|END", ExpectXML: `<LoadConfigResponse xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"><Result>SUCCESS</Result><parameters_loaded>14</parameters_loaded></LoadConfigResponse>`},
	{Value: pingMessage, ExpectASCII: "|GEMS|14|0000000067|1||1410819035.280000000|System/Device1|PING|END", ExpectXML: `<PingMessage xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"></PingMessage>`},
	{Value: pingResponse, ExpectASCII: "|GEMS|14|0000000078|1||1410819035.280000000|System/Device1|PING-R|SUCCESS||END", ExpectXML: `<PingResponse xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"><Result>SUCCESS</Result></PingResponse>`},
	{Value: saveConfigMessage, ExpectASCII: "|GEMS|14|0000000081|1||1410819035.280000000|System/Device1|SAVE|MySavedConfig|END", ExpectXML: `<SaveConfigMessage xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"><name>MySavedConfig</name></SaveConfigMessage>`},
	{Value: saveConfigResponse, ExpectASCII: "|GEMS|14|0000000081|1||1410819035.280000000|System/Device1|SAVE-R|SUCCESS||27|END", ExpectXML: `<SaveConfigResponse xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"><Result>SUCCESS</Result><parameters_saved>27</parameters_saved></SaveConfigResponse>`},
	{Value: setConfigMessageEscape, ExpectASCII: "|GEMS|14|0000000205|1||1410819035.270000000|System/Device1|SET|5|Ampersand:string=Bob &a Sally|Pipe:string=Bob &b Sally|Comma:string=Bob&c Sally|Semicolon:string=Bob&d Sally|LessThan:string=Bob < Sally|END", ExpectXML: `<SetConfigMessage xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.27"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="Ampersand"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Bob &amp; Sally</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="Pipe"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Bob | Sally</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="Comma"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Bob, Sally</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="Semicolon"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Bob; Sally</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="LessThan"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Bob &lt; Sally</string></Parameter></SetConfigMessage>`},
	{Value: setConfigMessageTypes, ExpectASCII: "|GEMS|14|0000001034|1||1410819035.270000000|System/Device1|SET|20|IntValue:int=1024|HexValue:hex_value=FAF320/24|BoolValue:bool=true|DoubleValue:double=1.234|LongValue:long=123456789|TimeValue:time=1410804178.490230000|UtimeValue:utime=2009-273T09:14:50.020000000Z|StringValue:string=My String|EmptyStringValue:string=|IntList:int[4]=1024,1,2,3|HexList:hex_value[2]=FAF320/24,EB90/16|BoolList:bool[3]=true,false,true|DoubleList:double[2]=1.234,11234567890|LongList:long[3]=123456789,-1,234569999|TimeList:time[2]=1410804178.490230000,1410804179.480470000|UtimeList:utime[2]=2009-273T09:14:50.020000000Z,2014-100T09:14:50.020000000Z|StringList:string[2]=Item 1,Item 2|EmptyStringList:string[0]=|SingleParameterSet:set_type=ChannelName:string=Channel0;ChannelID:int=0;BitRates:int[2]=200,2000;|ParameterSetList:set_type[3]=ChannelName:string=Channel0;ChannelID:int=0;BitRates:int[2]=200,2000;,ChannelName:string=Channel1;ChannelID:int=1;BitRates:int[2]=400,4000;,ChannelName:string=Channel2;ChannelID:int=2;BitRates:int[2]=600,6000;|END", ExpectXML: `<SetConfigMessage xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.27"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="IntValue"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1024</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="HexValue"><hex_value xmlns="http://www.omg.org/spec/gems/20110323/basetypes" bit_length="24">FAF320</hex_value></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BoolValue"><boolean xmlns="http://www.omg.org/spec/gems/20110323/basetypes">true</boolean></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="DoubleValue"><double xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1.234</double></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="LongValue"><long xmlns="http://www.omg.org/spec/gems/20110323/basetypes">123456789</long></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="TimeValue"><time xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1410804178.490230000</time></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="UtimeValue"><utime xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2009-273T09:14:50.020000000Z</utime></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="StringValue"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">My String</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="EmptyStringValue"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes"></string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="IntList" multiplicity="4"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1024</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">3</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="HexList" multiplicity="2"><hex_value xmlns="http://www.omg.org/spec/gems/20110323/basetypes" bit_length="24">FAF320</hex_value><hex_value xmlns="http://www.omg.org/spec/gems/20110323/basetypes" bit_length="16">EB90</hex_value></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BoolList" multiplicity="3"><boolean xmlns="http://www.omg.org/spec/gems/20110323/basetypes">true</boolean><boolean xmlns="http://www.omg.org/spec/gems/20110323/basetypes">false</boolean><boolean xmlns="http://www.omg.org/spec/gems/20110323/basetypes">true</boolean></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="DoubleList" multiplicity="2"><double xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1.234</double><double xmlns="http://www.omg.org/spec/gems/20110323/basetypes">11234567890</double></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="LongList" multiplicity="3"><long xmlns="http://www.omg.org/spec/gems/20110323/basetypes">123456789</long><long xmlns="http://www.omg.org/spec/gems/20110323/basetypes">-1</long><long xmlns="http://www.omg.org/spec/gems/20110323/basetypes">234569999</long></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="TimeList" multiplicity="2"><time xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1410804178.490230000</time><time xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1410804179.480470000</time></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="UtimeList" multiplicity="2"><utime xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2009-273T09:14:50.020000000Z</utime><utime xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2014-100T09:14:50.020000000Z</utime></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="StringList" multiplicity="2"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Item 1</string><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Item 2</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="EmptyStringList" multiplicity="0"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes"></string></Parameter><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="SingleParameterSet"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelName"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Channel0</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelID"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">0</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BitRates" multiplicity="2"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">200</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2000</int></Parameter></ParameterSet><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ParameterSetList" multiplicity="3"><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelName"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Channel0</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelID"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">0</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BitRates" multiplicity="2"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">200</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2000</int></Parameter></ParameterSet><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelName"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Channel1</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelID"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BitRates" multiplicity="2"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">400</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">4000</int></Parameter></ParameterSet><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelName"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Channel2</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelID"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BitRates" multiplicity="2"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">600</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">6000</int></Parameter></ParameterSet></ParameterSet></SetConfigMessage>`},
	{Value: setConfigResponse, ExpectASCII: "|GEMS|14|0000000079|1||1410819035.280000000|System/Device1|SET-R|SUCCESS||5|END", ExpectXML: `<SetConfigResponse xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" target="System/Device1" transaction_id="1" timestamp="1410819035.28"><Result>SUCCESS</Result><parameters_set>5</parameters_set></SetConfigResponse>`},
	{Value: unknownResponse, ExpectASCII: "|GEMS|14|0000000091|0||1410819035.260000000||UKN-R|MALFORMED_MESSAGE|Not a GEMS message|END", ExpectXML: `<UnknownResponse xmlns="http://www.omg.org/spec/gems/20110323/basetypes" gems_version="1.4" transaction_id="0" timestamp="1410819035.26"><Result>MALFORMED_MESSAGE</Result><description>Not a GEMS message</description></UnknownResponse>`},
}

func TestMarshalMessageXML(t *testing.T) {
	for idx, test := range messageMarshalTests {
		if test.UnmarshalOnly {
			continue
		}

		t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
			data, err := xml.Marshal(test.Value)
			if err != nil {
				if test.MarshalError == "" {
					t.Errorf("marshal(%#v): %s", test.Value, err)
					return
				}
				if !strings.Contains(err.Error(), test.MarshalError) {
					t.Errorf("marshal(%#v): %s, want %q", test.Value, err, test.MarshalError)
				}
				return
			}
			if test.MarshalError != "" {
				t.Errorf("Marshal succeeded, want error %q", test.MarshalError)
				return
			}
			if got, want := string(data), test.ExpectXML; got != want {
				if strings.Contains(want, "\n") {
					t.Errorf("marshal(%#v):\nhave:\n%s\nwant:\n%s", test.Value, got, want)
				} else {
					t.Errorf("marshal(%#v):\nhave %#q\nwant %#q", test.Value, got, want)
				}
			}
		})
	}
}

func TestUnmarshalMessageXML(t *testing.T) {
	for i, test := range messageMarshalTests {
		if test.MarshalOnly {
			continue
		}

		msg, err := gems.ReceiveXMLMessage([]byte(test.ExpectXML), v)

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			if err != nil {
				if test.UnmarshalError == "" {
					t.Errorf("unmarshal(%#v): %s", test.ExpectXML, err)
					return
				}
				if !strings.Contains(err.Error(), test.UnmarshalError) {
					t.Errorf("unmarshal(%#v): %s, want %q", test.ExpectXML, err, test.UnmarshalError)
				}
				return
			}
			if test.UnmarshalError != "" {
				t.Errorf("Unmarshal succeeded, want error %q", test.UnmarshalError)
				return
			}

			if got, want := msg, test.Value; !reflect.DeepEqual(got, want) {
				t.Errorf("unmarshal(%q):\nhave %#v\nwant %#v", test.ExpectXML, got, want)
			}
		})
	}
}

func TestMarshalMessageASCII(t *testing.T) {
	for idx, test := range messageMarshalTests {
		if test.UnmarshalOnly {
			continue
		}

		t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
			data, err := ascii.Marshal(test.Value)
			if err != nil {
				if test.MarshalError == "" {
					t.Errorf("marshal(%#v): %s", test.Value, err)
					return
				}
				if !strings.Contains(err.Error(), test.MarshalError) {
					t.Errorf("marshal(%#v): %s, want %q", test.Value, err, test.MarshalError)
				}
				return
			}
			if test.MarshalError != "" {
				t.Errorf("Marshal succeeded, want error %q", test.MarshalError)
				return
			}
			if got, want := string(data), test.ExpectASCII; got != want {
				if strings.Contains(want, "\n") {
					t.Errorf("marshal(%#v):\nHAVE:\n%s\nWANT:\n%s", test.Value, got, want)
				} else {
					t.Errorf("marshal(%#v):\nhave %#q\nwant %#q", test.Value, got, want)
				}
			}
		})
	}
}

func TestUnmarshalMessageASCII(t *testing.T) {
	for i, test := range messageMarshalTests {
		if test.MarshalOnly {
			continue
		}

		msg, err := gems.ReceiveASCIIMessage([]byte(test.ExpectASCII), v)

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			if err != nil {
				if test.UnmarshalError == "" {
					t.Errorf("unmarshal(%#v): %s", test.ExpectASCII, err)
					return
				}
				if !strings.Contains(err.Error(), test.UnmarshalError) {
					t.Errorf("unmarshal(%#v): %s, want %q", test.ExpectASCII, err, test.UnmarshalError)
				}
				return
			}
			if test.UnmarshalError != "" {
				t.Errorf("Unmarshal succeeded, want error %q", test.UnmarshalError)
				return
			}
			if got, want := msg, test.Value; !reflect.DeepEqual(got, want) {
				t.Errorf("unmarshal(%q):\nhave %#v\nwant %#v", test.ExpectASCII, got, want)
			}
		})
	}
}

var messageBuildTests = []struct {
	Builder gems.MessageBuilder
	Error   string
}{
	{Builder: v.NewMessageBuilder().Type(gems.UndefinedMessageType), Error: "build not implemented"},
}

func TestBuildMessages(t *testing.T) {
	for i, test := range messageBuildTests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			p, err := test.Builder.Build()
			if err == nil {
				t.Errorf("Build succeeded (%#v), want error %q", p, test.Error)
				return
			}
			if !strings.Contains(err.Error(), test.Error) {
				t.Errorf("incorrect error:\nhave: %s,\nwant: %q", err, test.Error)

			}
		})
	}
}
