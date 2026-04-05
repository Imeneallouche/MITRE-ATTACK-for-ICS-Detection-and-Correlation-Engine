package gemsV14_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mitre/gems/src/ascii"
	"github.com/mitre/gems/src/gemsV14"
)

var (
	// reserved, _         = gemsV14.NewParameterBuilder().Name("|GEMS").String("MyString").Build()
	nonASCII, _         = gemsV14.NewParameterBuilder().Name("StringValue").String("你好，🌍").Build()
	invalidParameter, _ = gemsV14.NewParameterBuilder().Name("Invalid").String("Invalid").Build()
	tricky, _           = gemsV14.NewParameterBuilder().Name("TrickyString").String(":string=MyString").Build()
	escaped, _          = gemsV14.NewParameterBuilder().Name("Escape&|,;Chars").String("& | , ;").Build()

	invalidResponse = gemsV14.UnknownResponse{}
	// invalidGet      = gemsV14.GetConfigMessage{}
	// invalidGetR     = gemsV14.GetConfigResponse{}
)

var asciiTests = []struct {
	Value          any
	ExpectASCII    string
	MarshalOnly    bool
	MarshalError   string
	UnmarshalOnly  bool
	UnmarshalError string
}{
	// {Value: reserved, MarshalOnly: true, MarshalError: "reserved word"},
	{Value: nonASCII, MarshalOnly: true, MarshalError: "non-ASCII characters"},

	{Value: invalidParameter, ExpectASCII: "Invalidbool=true", UnmarshalOnly: true, UnmarshalError: "missing ':'"},
	{Value: invalidParameter, ExpectASCII: "Invalid:integer=10", UnmarshalOnly: true, UnmarshalError: "invalid value type"},

	{Value: invalidParameter, ExpectASCII: "Invalid:bool[]=true,false", UnmarshalOnly: true, UnmarshalError: "invalid type string"},
	{Value: invalidParameter, ExpectASCII: "Invalid:bool[2=true,false", UnmarshalOnly: true, UnmarshalError: "invalid type string"},
	{Value: invalidParameter, ExpectASCII: "Invalid:bool[2] =true,false", UnmarshalOnly: true, UnmarshalError: "invalid type string"},
	{Value: invalidParameter, ExpectASCII: "Invalid:bool[two]=true,false", UnmarshalOnly: true, UnmarshalError: "invalid multiplicity"},

	{Value: tricky, ExpectASCII: "TrickyString:string=:string=MyString"},
	{Value: escaped, ExpectASCII: "Escape&a&b&c&dChars:string=&a &b &c &d"},

	{Value: &invalidResponse, ExpectASCII: "|GEM|14|0000000101|0|token|1410819035.260000000|Target|UKN-R|MALFORMED_MESSAGE|Not a GEMS message|END", UnmarshalOnly: true, UnmarshalError: "invalid start"},
	{Value: &invalidResponse, ExpectASCII: "|GEMS|14|0000000099|0|token|1410819035.260000000|Target|UKN-R|MALFORMED_MESSAGE|Not a GEMS message|", UnmarshalOnly: true, UnmarshalError: "message trailer"},
	{Value: &invalidResponse, ExpectASCII: "|GEMS|14|000000000A|0|token|1410819035.260000000|Target|UKN-R|MALFORMED_MESSAGE|Not a GEMS message|END", UnmarshalOnly: true, UnmarshalError: "invalid message length"},
	{Value: &invalidResponse, ExpectASCII: "|GEMS|14|0000000001|0|token|1410819035.260000000|Target|UKN-R|MALFORMED_MESSAGE|Not a GEMS message|END", UnmarshalOnly: true, UnmarshalError: "message length field does not match"},
	{Value: &invalidResponse, ExpectASCII: "|GEMS|14|0000000052|0|token|1410819035.260000000|END", UnmarshalOnly: true, UnmarshalError: "incomplete"},
	{Value: &invalidResponse, ExpectASCII: "|GEMS|14|0000000059|0|token|1410819035.260000000|Target|END", UnmarshalOnly: true, UnmarshalError: "incomplete"},
	{Value: &invalidResponse, ExpectASCII: "|GEMS|14|0000000104|BAD|token|1410819035.260000000|Target|UKN-R|MALFORMED_MESSAGE|Not a GEMS message|END", UnmarshalOnly: true, UnmarshalError: "invalid Transaction ID"},
	{Value: &invalidResponse, ExpectASCII: "|GEMS|14|0000000086|0|token|7:51|Target|UKN-R|MALFORMED_MESSAGE|Not a GEMS message|END", UnmarshalOnly: true, UnmarshalError: "invalid syntax"},
	{Value: &invalidResponse, ExpectASCII: "|GEMS|14|0000000101|0|token|1410819035.260000000|Target|UKNR|MALFORMED_MESSAGE|Not a GEMS message|END", UnmarshalOnly: true, UnmarshalError: "invalid type"},
	{Value: &invalidResponse, ExpectASCII: "|GEMS|14|0000000083|0|token|1410819035.260000000|Target|UKN-R|MALFORMED_MESSAGE|END", UnmarshalOnly: true, UnmarshalError: "incomplete"},
	{Value: &invalidResponse, ExpectASCII: "|GEMS|14|0000000023|END", UnmarshalOnly: true, UnmarshalError: "incomplete"},
	// {Value: &invalidGet, ExpectASCII: "|GEMS|14|0000000109|1||1410819035.28000000|System/Device1|GET|4|PacketLength|FillPacket|ChannelConfigList|END", UnmarshalOnly: true, UnmarshalError: "invalid number of parameters"},
	// {Value: &invalidGetR, ExpectASCII: "|GEMS|14|0000000384|1||1410819035.28000000|System/Device1|GET-R|||4|PacketLength:int=1024|FillPacket:bool=True|EmptyStringList:string[0]=|EmptyIntList:int[0]=|ChannelConfigList:set_type[3]=ChannelName:string=Channel0;ChannelID:int=0;BitRate:int=200000;,ChannelName:string=Channel1;ChannelID:int=1;BitRate:int=400000;,ChannelName:string=Channel2;ChannelID:int=2;BitRate:int=600000;|END", UnmarshalOnly: true, UnmarshalError: "invalid number of parameters"},
}

func TestASCIIMarshal(t *testing.T) {
	for idx, test := range asciiTests {
		if test.UnmarshalOnly {
			continue
		}

		t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
			in, ok := test.Value.(ascii.Marshaler)
			if !ok {
				t.Errorf("marshal(%#v): does not implement ASCIIMarshaler", test.Value)
			}
			data, err := ascii.Marshal(in)
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
				t.Errorf("Marshal succeeded (%#v)\nwant error %q", data, test.MarshalError)
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

func TestASCIIUnmarshal(t *testing.T) {
	for i, test := range asciiTests {
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
				t.Errorf("Unmarshal succeeded (%#v)\nwant error %q", dest, test.UnmarshalError)
				return
			}
			if got, want := dest, test.Value; !reflect.DeepEqual(got, want) {
				t.Errorf("unmarshal(%q):\nhave: %#v\nwant: %#v", test.ExpectASCII, got, want)
			}
		})
	}
}
