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
	empty, _ = gemsV14.NewParameterBuilder().Build()

	emptyParameterList, _ = gemsV14.NewParameterBuilder().Name("EmptyVersion1").Parameters().Build()

	stringValue, _ = gemsV14.NewParameterBuilder().Name("StringValue").String("My String").Build()
	hexValue, _    = gemsV14.NewParameterBuilder().Name("HexValue").HexValue("FAF320/24").Build()
	boolValue, _   = gemsV14.NewParameterBuilder().Name("BoolValue").Boolean(true).Build()
	byteValue, _   = gemsV14.NewParameterBuilder().Name("ByteValue").Byte(127).Build()
	ubyteValue, _  = gemsV14.NewParameterBuilder().Name("UbyteValue").Ubyte(255).Build()
	shortValue, _  = gemsV14.NewParameterBuilder().Name("ShortValue").Short(12).Build()
	ushortValue, _ = gemsV14.NewParameterBuilder().Name("UshortValue").Ushort(12).Build()
	intValue, _    = gemsV14.NewParameterBuilder().Name("IntValue").Int(1024).Build()
	uintValue, _   = gemsV14.NewParameterBuilder().Name("UintValue").Uint(123).Build()
	longValue, _   = gemsV14.NewParameterBuilder().Name("LongValue").Long(123456789).Build()
	ulongValue, _  = gemsV14.NewParameterBuilder().Name("UlongValue").Ulong(123456789).Build()
	doubleValue, _ = gemsV14.NewParameterBuilder().Name("DoubleValue").Double(1.234).Build()
	timeValue, _   = gemsV14.NewParameterBuilder().Name("TimeValue").Time("1410804178.49023000").Build()
	utimeValue, _  = gemsV14.NewParameterBuilder().Name("UtimeValue").Utime("2009-273T09:14:50.02Z").Build()

	emptyStringValue, _ = gemsV14.NewParameterBuilder().Name("EmptyStringValue").String().Build()

	intList, _    = gemsV14.NewParameterBuilder().Name("IntList").Int(1024, 1, 2, 3).Build()
	hexList, _    = gemsV14.NewParameterBuilder().Name("HexList").HexValue("FAF320/24", "EB90/16").Build()
	boolList, _   = gemsV14.NewParameterBuilder().Name("BoolList").Boolean(true, false, true).Build()
	doubleList, _ = gemsV14.NewParameterBuilder().Name("DoubleList").Double(1.234, 11234567890.0).Build()
	longList, _   = gemsV14.NewParameterBuilder().Name("LongList").Long(123456789, -1, 234569999).Build()
	timeList, _   = gemsV14.NewParameterBuilder().Name("TimeList").Time("1410804178.49023000", "1410804179.48047000").Build()
	utimeList, _  = gemsV14.NewParameterBuilder().Name("UtimeList").Utime("2009-273T09:14:50.02Z", "2014-100T09:14:50.02Z").Build()
	stringList, _ = gemsV14.NewParameterBuilder().Name("StringList").String("Item 1", "Item 2").Build()

	emptyStringList, _ = gemsV14.NewParameterBuilder().Name("EmptyStringList").String().Multiplicity(0).Build()
	emptyIntList, _    = gemsV14.NewParameterBuilder().Name("EmptyIntList").Int().Multiplicity(0).Build()

	xmlEscapeString, _ = gemsV14.NewParameterBuilder().Name("Escape<>Me").String("Escape&This").Build()

	channel0Name, _       = gemsV14.NewParameterBuilder().Name("ChannelName").String("Channel0").Build()
	channel0Id, _         = gemsV14.NewParameterBuilder().Name("ChannelID").Int(0).Build()
	channel0BitRates, _   = gemsV14.NewParameterBuilder().Name("BitRates").Int(200, 2000).Build()
	singleParameterSet, _ = gemsV14.NewParameterBuilder().Name("SingleParameterSet").Parameters(channel0Name, channel0Id, channel0BitRates).Build()
	channel0, _           = gemsV14.NewParameterBuilder().Name("").Parameters(channel0Name, channel0Id, channel0BitRates).Build()

	channel1Name, _     = gemsV14.NewParameterBuilder().Name("ChannelName").String("Channel1").Build()
	channel1Id, _       = gemsV14.NewParameterBuilder().Name("ChannelID").Int(1).Build()
	channel1BitRates, _ = gemsV14.NewParameterBuilder().Name("BitRates").Int(400, 4000).Build()
	channel1, _         = gemsV14.NewParameterBuilder().Name("").Parameters(channel1Name, channel1Id, channel1BitRates).Build()

	channel2Name, _     = gemsV14.NewParameterBuilder().Name("ChannelName").String("Channel2").Build()
	channel2Id, _       = gemsV14.NewParameterBuilder().Name("ChannelID").Int(2).Build()
	channel2BitRates, _ = gemsV14.NewParameterBuilder().Name("BitRates").Int(600, 6000).Build()
	channel2, _         = gemsV14.NewParameterBuilder().Name("").Parameters(channel2Name, channel2Id, channel2BitRates).Build()
	parameterSetList, _ = gemsV14.NewParameterBuilder().Name("ParameterSetList").Parameters(channel0, channel1, channel2).Build()
)

// Round trip encoding tests replicated from go/encoding/xml
var parameterMarshalTests = []struct {
	Value          gems.Parameter
	ExpectASCII    string
	ExpectXML      string
	MarshalOnly    bool
	MarshalError   string
	UnmarshalOnly  bool
	UnmarshalError string
}{
	{Value: empty, ExpectASCII: "", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes"></Parameter>`},
	{Value: emptyParameterList, ExpectASCII: "EmptyVersion1:set_type=;", ExpectXML: `<ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="EmptyVersion1"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes"></Parameter></ParameterSet>`},

	{Value: stringValue, ExpectASCII: "StringValue:string=My String", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="StringValue"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">My String</string></Parameter>`},
	{Value: hexValue, ExpectASCII: "HexValue:hex_value=FAF320/24", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="HexValue"><hex_value xmlns="http://www.omg.org/spec/gems/20110323/basetypes" bit_length="24">FAF320</hex_value></Parameter>`},
	{Value: boolValue, ExpectASCII: "BoolValue:bool=true", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BoolValue"><boolean xmlns="http://www.omg.org/spec/gems/20110323/basetypes">true</boolean></Parameter>`},
	{Value: byteValue, ExpectASCII: "ByteValue:byte=127", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ByteValue"><byte xmlns="http://www.omg.org/spec/gems/20110323/basetypes">127</byte></Parameter>`},
	{Value: ubyteValue, ExpectASCII: "UbyteValue:ubyte=255", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="UbyteValue"><ubyte xmlns="http://www.omg.org/spec/gems/20110323/basetypes">255</ubyte></Parameter>`},
	{Value: shortValue, ExpectASCII: "ShortValue:short=12", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ShortValue"><short xmlns="http://www.omg.org/spec/gems/20110323/basetypes">12</short></Parameter>`},
	{Value: ushortValue, ExpectASCII: "UshortValue:ushort=12", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="UshortValue"><ushort xmlns="http://www.omg.org/spec/gems/20110323/basetypes">12</ushort></Parameter>`},
	{Value: intValue, ExpectASCII: "IntValue:int=1024", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="IntValue"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1024</int></Parameter>`},
	{Value: uintValue, ExpectASCII: "UintValue:uint=123", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="UintValue"><uint xmlns="http://www.omg.org/spec/gems/20110323/basetypes">123</uint></Parameter>`},
	{Value: longValue, ExpectASCII: "LongValue:long=123456789", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="LongValue"><long xmlns="http://www.omg.org/spec/gems/20110323/basetypes">123456789</long></Parameter>`},
	{Value: ulongValue, ExpectASCII: "UlongValue:ulong=123456789", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="UlongValue"><ulong xmlns="http://www.omg.org/spec/gems/20110323/basetypes">123456789</ulong></Parameter>`},
	{Value: doubleValue, ExpectASCII: "DoubleValue:double=1.234", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="DoubleValue"><double xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1.234</double></Parameter>`},
	{Value: timeValue, ExpectASCII: "TimeValue:time=1410804178.490230000", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="TimeValue"><time xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1410804178.490230000</time></Parameter>`},
	{Value: utimeValue, ExpectASCII: "UtimeValue:utime=2009-273T09:14:50.020000000Z", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="UtimeValue"><utime xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2009-273T09:14:50.020000000Z</utime></Parameter>`},

	{Value: boolList, ExpectASCII: "BoolList:bool[3]=true,false,true", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BoolList" multiplicity="3"><boolean xmlns="http://www.omg.org/spec/gems/20110323/basetypes">true</boolean><boolean xmlns="http://www.omg.org/spec/gems/20110323/basetypes">false</boolean><boolean xmlns="http://www.omg.org/spec/gems/20110323/basetypes">true</boolean></Parameter>`},
	{Value: hexList, ExpectASCII: "HexList:hex_value[2]=FAF320/24,EB90/16", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="HexList" multiplicity="2"><hex_value xmlns="http://www.omg.org/spec/gems/20110323/basetypes" bit_length="24">FAF320</hex_value><hex_value xmlns="http://www.omg.org/spec/gems/20110323/basetypes" bit_length="16">EB90</hex_value></Parameter>`},
	{Value: intList, ExpectASCII: "IntList:int[4]=1024,1,2,3", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="IntList" multiplicity="4"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1024</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">3</int></Parameter>`},
	{Value: doubleList, ExpectASCII: "DoubleList:double[2]=1.234,11234567890", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="DoubleList" multiplicity="2"><double xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1.234</double><double xmlns="http://www.omg.org/spec/gems/20110323/basetypes">11234567890</double></Parameter>`},
	{Value: longList, ExpectASCII: "LongList:long[3]=123456789,-1,234569999", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="LongList" multiplicity="3"><long xmlns="http://www.omg.org/spec/gems/20110323/basetypes">123456789</long><long xmlns="http://www.omg.org/spec/gems/20110323/basetypes">-1</long><long xmlns="http://www.omg.org/spec/gems/20110323/basetypes">234569999</long></Parameter>`},
	{Value: timeList, ExpectASCII: "TimeList:time[2]=1410804178.490230000,1410804179.480470000", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="TimeList" multiplicity="2"><time xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1410804178.490230000</time><time xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1410804179.480470000</time></Parameter>`},
	{Value: utimeList, ExpectASCII: "UtimeList:utime[2]=2009-273T09:14:50.020000000Z,2014-100T09:14:50.020000000Z", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="UtimeList" multiplicity="2"><utime xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2009-273T09:14:50.020000000Z</utime><utime xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2014-100T09:14:50.020000000Z</utime></Parameter>`},
	{Value: stringList, ExpectASCII: "StringList:string[2]=Item 1,Item 2", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="StringList" multiplicity="2"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Item 1</string><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Item 2</string></Parameter>`},

	{Value: emptyStringValue, ExpectASCII: "EmptyStringValue:string=", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="EmptyStringValue"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes"></string></Parameter>`},
	{Value: emptyStringList, ExpectASCII: "EmptyStringList:string[0]=", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="EmptyStringList" multiplicity="0"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes"></string></Parameter>`},
	{Value: emptyIntList, ExpectASCII: "EmptyIntList:int[0]=", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="EmptyIntList" multiplicity="0"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes"></int></Parameter>`},

	{Value: singleParameterSet, ExpectASCII: "SingleParameterSet:set_type=ChannelName:string=Channel0;ChannelID:int=0;BitRates:int[2]=200,2000;", ExpectXML: `<ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="SingleParameterSet"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelName"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Channel0</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelID"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">0</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BitRates" multiplicity="2"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">200</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2000</int></Parameter></ParameterSet>`},
	{Value: parameterSetList, ExpectASCII: "ParameterSetList:set_type[3]=ChannelName:string=Channel0;ChannelID:int=0;BitRates:int[2]=200,2000;,ChannelName:string=Channel1;ChannelID:int=1;BitRates:int[2]=400,4000;,ChannelName:string=Channel2;ChannelID:int=2;BitRates:int[2]=600,6000;", ExpectXML: `<ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ParameterSetList" multiplicity="3"><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelName"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Channel0</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelID"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">0</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BitRates" multiplicity="2"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">200</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2000</int></Parameter></ParameterSet><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelName"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Channel1</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelID"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">1</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BitRates" multiplicity="2"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">400</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">4000</int></Parameter></ParameterSet><ParameterSet xmlns="http://www.omg.org/spec/gems/20110323/basetypes"><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelName"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Channel2</string></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="ChannelID"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">2</int></Parameter><Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="BitRates" multiplicity="2"><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">600</int><int xmlns="http://www.omg.org/spec/gems/20110323/basetypes">6000</int></Parameter></ParameterSet></ParameterSet>`},

	{Value: xmlEscapeString, ExpectASCII: "Escape<>Me:string=Escape&aThis", ExpectXML: `<Parameter xmlns="http://www.omg.org/spec/gems/20110323/basetypes" name="Escape&lt;&gt;Me"><string xmlns="http://www.omg.org/spec/gems/20110323/basetypes">Escape&amp;This</string></Parameter>`},
}

func TestMarshalParameterXML(t *testing.T) {
	for idx, test := range parameterMarshalTests {
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

func TestMarshalParameterASCII(t *testing.T) {
	for idx, test := range parameterMarshalTests {
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
					t.Errorf("marshal(%#v):\nhave:\n%s\nwant:\n%s", test.Value, got, want)
				} else {
					t.Errorf("marshal(%#v):\nhave %#q\nwant %#q", test.Value, got, want)
				}
			}
		})
	}
}

func TestUnmarshalParameterXML(t *testing.T) {
	for i, test := range parameterMarshalTests {
		if test.MarshalOnly {
			continue
		}

		vt := reflect.TypeOf(test.Value)
		dest := reflect.New(vt.Elem()).Interface()
		err := xml.Unmarshal([]byte(test.ExpectXML), dest)

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
			if got, want := dest, test.Value; !reflect.DeepEqual(got, want) {
				t.Errorf("unmarshal(%q):\nhave %#v\nwant %#v", test.ExpectXML, got, want)
			}
		})
	}
}

func TestUnmarshalParameterASCII(t *testing.T) {
	for i, test := range parameterMarshalTests {
		if test.MarshalOnly {
			continue
		}

		vt := reflect.TypeOf(test.Value)
		dest := reflect.New(vt.Elem()).Interface()
		err := ascii.Unmarshal([]byte(test.ExpectASCII), dest)

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
			if got, want := dest, test.Value; !reflect.DeepEqual(got, want) {
				t.Errorf("unmarshal(%q):\nhave %#v\nwant %#v", test.ExpectASCII, got, want)
			}
		})
	}
}

var parameterBuildErrors = []struct {
	Builder *gemsV14.ParameterBuilder
	Error   string
}{
	{Builder: gemsV14.NewParameterBuilder().Name("Invalid Name").String("Test"), Error: "cannot contain spaces"},
	{Builder: gemsV14.NewParameterBuilder().Name("Non-ASCII").String("你哈世界"), Error: "non-ASCII characters"},
}

func TestBuildParameter(t *testing.T) {
	for i, test := range parameterBuildErrors {
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
