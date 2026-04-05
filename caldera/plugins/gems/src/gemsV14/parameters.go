package gemsV14

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	gems "github.com/mitre/gems/src"
	"github.com/mitre/gems/src/ascii"
)

func getASCIIParameterType(data []byte) gems.Datatype {
	header, _, found := bytes.Cut(data, []byte("="))
	if !found {
		return gems.UndefinedType
	}

	idx := bytes.LastIndex(header, []byte(":"))
	if idx == -1 {
		return gems.UndefinedType
	}

	typ := header[idx+1:]
	idx = bytes.IndexAny(typ, "[(")
	if idx == -1 {
		return gems.DatatypeFromASCII(string(typ))
	}

	return gems.DatatypeFromASCII(string(typ[:idx]))
}

func UnmarshalParameterASCII(data []byte) (gems.XMLParameter, error) {
	typ := getASCIIParameterType(data)
	switch typ {
	case gems.ParameterSetType:
		p := newEmptyParameterSet()
		err := ascii.Unmarshal(data, p)
		return p, err
	default:
		p := newEmptyParameter()
		err := ascii.Unmarshal(data, p)
		return p, err
	}
}

func unmarshalParameterSliceASCII(fields [][]byte) ([]gems.XMLParameter, error) {
	var params []gems.XMLParameter

	if len(fields) < 1 {
		return params, &ascii.UnmarshalError{Data: bytes.Join(fields, []byte("|")), Msg: "invalid message content"}
	}

	paramCount, err := strconv.Atoi(string(fields[0]))
	if (err != nil) || (paramCount != len(fields)-1) {
		return params, &ascii.UnmarshalError{Data: bytes.Join(fields, []byte("|")), Msg: "invalid number of parameters"}
	}

	for i := range paramCount {
		p, err := UnmarshalParameterASCII(fields[i+1])
		if err != nil {
			return params, err
		}
		params = append(params, p)
	}
	return params, nil
}

// Parameter is a representation of a GEMS Parameter
// as defined by Version 1.4 of the GEMS specification.
type Parameter struct {
	Values       ValueSlice
	Multiplicity gems.NullInt32
	name         string
	typeAttr     gems.Datatype
}

func newEmptyParameter() *Parameter {
	return &Parameter{Values: make(ValueSlice, 0)}
}

func (p Parameter) Name() string {
	return p.name
}

func (p Parameter) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = gems.ParameterType.XMLName()
	if p.name != "" {
		nameAttr := xml.Attr{Name: xml.Name{Local: "name"}, Value: p.name}
		start.Attr = append(start.Attr, nameAttr)
	}
	if p.typeAttr != gems.UndefinedType {
		typeAttr := xml.Attr{Name: xml.Name{Local: "type"}, Value: p.typeAttr.XMLName().Local}
		start.Attr = append(start.Attr, typeAttr)
	}
	if p.Multiplicity.Valid {
		multiplicityAttr, _ := p.Multiplicity.MarshalXMLAttr(xml.Name{Local: "multiplicity"})
		start.Attr = append(start.Attr, multiplicityAttr)
	}

	e.EncodeToken(start)
	for _, v := range p.Values {
		e.EncodeElement(v, xml.StartElement{Name: v.Type().XMLName()})
	}
	e.EncodeToken(start.End())
	return nil
}

func (p *Parameter) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		switch attr.Name.Local {
		case "name":
			p.name = attr.Value
		case "type":
			p.typeAttr = gems.DatatypeFromXML(attr.Value)
		case "multiplicity":
			if err := p.Multiplicity.UnmarshalXMLAttr(attr); err != nil {
				return err
			}
		}
	}

	vals := ValueSlice{}

tokenLoop:
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch se := t.(type) {
		case xml.StartElement:
			typ := gems.DatatypeFromXML(se.Name.Local)
			v, err := newValue(typ)
			if err != nil {
				continue
			}
			if err := d.DecodeElement(v, &se); err != nil {
				return err
			}
			vals = append(vals, v)
		case xml.EndElement:
			if se == start.End() {
				break tokenLoop
			}
		}
	}

	p.Values = vals
	return nil
}

func (p Parameter) MarshalASCII(b *ascii.Buffer) error {
	err := b.SafeWrite(escape(p.name))
	if err != nil {
		return err
	}

	switch typ := p.ValueType(); typ {
	case gems.UndefinedType:
		if len(p.Values) == 0 {
			return nil
		}
		return &ascii.MarshalError{Msg: "cannot marshal a Parameter of undefined type"}
	default:
		_, err = fmt.Fprintf(b, ":%s", typ.ASCIIName())
		if err != nil {
			return &ascii.MarshalError{Msg: err.Error()}
		}
	}

	switch p.Multiplicity.Valid {
	case false:
		_, err = fmt.Fprint(b, "=")
	default:
		_, err = fmt.Fprintf(b, "[%d]=", p.Multiplicity.Int32)
	}
	if err != nil {
		return &ascii.MarshalError{Msg: err.Error()}
	}

	return p.Values.MarshalASCII(b)
}

func (p *Parameter) UnmarshalASCII(data []byte) error {
	p.Values = make(ValueSlice, 0)
	header, values, found := bytes.Cut(data, []byte("="))
	if !found {
		name := string(header)
		name = unescape(name)
		p.name = name
		return nil
	}

	idx := bytes.LastIndex(header, []byte(":"))
	if idx == -1 {
		return &ascii.UnmarshalError{Data: data, Msg: "parameter missing ':' separator"}
	}

	name := string(header[:idx])
	name = unescape(name)
	p.name = name
	p.Multiplicity = gems.NullInt32{}

	typ := header[idx+1:]
	idx = bytes.IndexRune(typ, '[')
	if idx != -1 {
		lastByte := typ[len(typ)-1]
		if (lastByte != byte(']')) || (idx > len(typ)-3) {
			return &ascii.UnmarshalError{Data: typ, Msg: "invalid type string"}
		}

		multiplicityBytes := typ[idx+1 : len(typ)-1]
		multiplicity, err := strconv.ParseInt(string(multiplicityBytes), 10, 32)
		if err != nil {
			return &ascii.UnmarshalError{Data: multiplicityBytes, Msg: "invalid multiplicity value"}
		}
		p.Multiplicity = gems.NewNullInt32(int(multiplicity))

		typ = typ[:idx]
	}

	valueType := gems.DatatypeFromASCII(string(typ))
	if valueType == gems.UndefinedType {
		return &ascii.UnmarshalError{Data: typ, Msg: "invalid value type"}
	}

	splitData := bytes.Split(values, []byte(","))
	if err := p.Values.unmarshalASCII(splitData, valueType); err != nil {
		return err
	}

	return nil
}

func (p Parameter) Type() gems.Datatype {
	return gems.ParameterType
}

func (p Parameter) ValueType() gems.Datatype {
	typ := gems.UndefinedType
	for i := range len(p.Values) {
		if typ == gems.UndefinedType {
			typ = p.Values[i].Type()
		}

		if typ != p.Values[i].Type() {
			return gems.UndefinedType
		}
	}

	return typ
}

func (p Parameter) Validate() error {
	if strings.ContainsAny(p.name, " \t\n\r\v\f") {
		return fmt.Errorf("Parameter name cannot contain spaces")
	}

	nValues := len(p.Values)
	if !p.Multiplicity.Valid && (nValues > 1) {
		return fmt.Errorf("scalar Parameter contains multiple values")
	}

	if p.Multiplicity.Valid && (nValues > int(p.Multiplicity.Int32)) && p.Multiplicity.Int32 != int32(-1) {
		return fmt.Errorf("array Parameter has invalid multiplicity value")
	}

	for i := range nValues {
		if !ascii.Valid(p.Values[i].String()) {
			return fmt.Errorf("Parameter contains non-ASCII characters")
		}
	}

	if nValues == 0 {
		return nil
	}

	typ := p.ValueType()
	switch typ {
	case gems.UndefinedType:
		return fmt.Errorf("Parameter contains inconsistent or undefined value types")
	case gems.ParameterType, gems.ParameterSetType:
		return fmt.Errorf("Parameter contains Parameter or ParameterSet values")
	}

	return nil
}

func (a Parameter) String() string {
	var b ascii.Buffer
	a.MarshalASCII(&b)
	return b.String()
}

// ParameterSet is a representation of a GEMS ParameterSet
// as defined by Version 1.4 of the GEMS specification.
type ParameterSet struct {
	Values       ValueSlice
	Multiplicity gems.NullInt32
	name         string
	typeAttr     gems.Datatype
}

func newEmptyParameterSet() *ParameterSet {
	return &ParameterSet{Values: make(ValueSlice, 0)}
}

func (ps ParameterSet) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = gems.ParameterSetType.XMLName()
	if ps.name != "" {
		nameAttr := xml.Attr{Name: xml.Name{Local: "name"}, Value: ps.name}
		start.Attr = append(start.Attr, nameAttr)
	}
	if ps.typeAttr != gems.UndefinedType {
		typeAttr := xml.Attr{Name: xml.Name{Local: "type"}, Value: ps.typeAttr.XMLName().Local}
		start.Attr = append(start.Attr, typeAttr)
	}
	if ps.Multiplicity.Valid {
		multiplicityAttr, _ := ps.Multiplicity.MarshalXMLAttr(xml.Name{Local: "multiplicity"})
		start.Attr = append(start.Attr, multiplicityAttr)
	}

	e.EncodeToken(start)
	for _, v := range ps.Values {
		switch v.Type() {
		case gems.ParameterSetType:
			cs, ok := v.(*ParameterSet)
			if !ok {
				return fmt.Errorf("error marshaling parameter set")
			}
			// The specification requires the attributes of child parameter sets be ignored.
			cs.name = ""
			cs.typeAttr = gems.UndefinedType
			cs.Multiplicity.Valid = false
			e.EncodeElement(cs, xml.StartElement{Name: gems.ParameterSetType.XMLName()})
		default:
			e.EncodeElement(v, xml.StartElement{Name: v.Type().XMLName()})
		}
	}
	e.EncodeToken(start.End())
	return nil
}

func (p *ParameterSet) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		switch attr.Name.Local {
		case "name":
			p.name = attr.Value
		case "type":
			p.typeAttr = gems.DatatypeFromXML(attr.Value)
		case "multiplicity":
			if err := p.Multiplicity.UnmarshalXMLAttr(attr); err != nil {
				return err
			}
		}
	}

	vals := ValueSlice{}
tokenLoop:
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch se := t.(type) {
		case xml.StartElement:
			typ := gems.DatatypeFromXML(se.Name.Local)
			v, err := newValue(typ)
			if err != nil {
				continue
			}
			if err := d.DecodeElement(v, &se); err != nil {
				return err
			}
			vals = append(vals, v)
		case xml.EndElement:
			if se == start.End() {
				break tokenLoop
			}
		}
	}

	p.Values = vals
	return nil
}

func (ps ParameterSet) MarshalASCII(b *ascii.Buffer) error {
	err := b.SafeWrite(escape(ps.name))
	if err != nil {
		return err
	}

	switch ps.Multiplicity.Valid {
	case false:
		_, err = fmt.Fprintf(b, ":%s=", gems.ParameterSetType.ASCIIName())
	default:
		_, err = fmt.Fprintf(b, ":%s[%d]=", gems.ParameterSetType.ASCIIName(), ps.Multiplicity.Int32)
	}
	if err != nil {
		return &ascii.MarshalError{Msg: err.Error()}
	}

	return ps.Values.MarshalASCII(b)
}

func (ps *ParameterSet) UnmarshalASCII(data []byte) error {
	ps.Values = make(ValueSlice, 0)
	header, values, found := bytes.Cut(data, []byte("="))
	if !found {
		name := string(header)
		name = unescape(name)
		ps.name = name
		return nil
	}

	idx := bytes.LastIndex(header, []byte(":"))
	if idx == -1 {
		return &ascii.UnmarshalError{Data: data, Msg: "parameter missing ':' separator"}
	}

	name := string(header[:idx])
	name = unescape(name)
	ps.name = name
	ps.Multiplicity = gems.NullInt32{}

	typ := header[idx+1:]
	idx = bytes.IndexRune(typ, '[')
	if idx != -1 {
		lastByte := typ[len(typ)-1]
		if (lastByte != byte(']')) || (idx > len(typ)-3) {
			return &ascii.UnmarshalError{Data: typ, Msg: "invalid type string"}
		}

		multiplicityBytes := typ[idx+1 : len(typ)-1]
		multiplicity, err := strconv.ParseInt(string(multiplicityBytes), 10, 32)
		if err != nil {
			return &ascii.UnmarshalError{Data: multiplicityBytes, Msg: "invalid multiplicity value"}
		}
		ps.Multiplicity = gems.NewNullInt32(int(multiplicity))

		typ = typ[:idx]
		if gems.DatatypeFromASCII(string(typ)) != gems.ParameterSetType {
			return &ascii.UnmarshalError{Data: typ, Msg: "unexpected type for ParameterSet"}
		}
	}

	if len(values) == 0 {
		return nil
	}

	values = bytes.TrimSuffix(values, []byte(";"))
	if ps.Multiplicity.Valid {
		setSplit := bytes.Split(values, []byte(";,"))
		for _, setData := range setSplit {
			childSet := newEmptyParameterSet()
			splitData := bytes.Split(setData, []byte(";"))
			if err := childSet.Values.unmarshalASCII(splitData, gems.ParameterType); err != nil {
				return err
			}
			ps.Values = append(ps.Values, childSet)
		}
	} else {
		splitData := bytes.Split(values, []byte(";"))
		if err := ps.Values.unmarshalASCII(splitData, gems.ParameterType); err != nil {
			return err
		}
	}

	return nil
}

func (ps ParameterSet) Type() gems.Datatype {
	return gems.ParameterSetType
}

func (ps ParameterSet) Name() string {
	return ps.name
}

func (ps ParameterSet) ValueType() gems.Datatype {
	typ := gems.UndefinedType
	for i := range len(ps.Values) {
		if typ == gems.UndefinedType {
			typ = ps.Values[i].Type()
		}

		if typ != ps.Values[i].Type() {
			return gems.UndefinedType
		}
	}

	return typ
}

func (ps ParameterSet) Validate() error {
	if strings.ContainsAny(ps.name, " \t\n\r\v\f") {
		return fmt.Errorf("ParameterSet name cannot contain spaces")
	}

	nValues := len(ps.Values)
	if !ps.Multiplicity.Valid && (nValues > 1) {
		return fmt.Errorf("scalar ParameterSet contains multiple values")
	}

	if ps.Multiplicity.Valid && (nValues > int(ps.Multiplicity.Int32)) && ps.Multiplicity.Int32 != int32(-1) {
		return fmt.Errorf("array ParameterSet has invalid multiplicity value")
	}

	for i := range nValues {
		if !ascii.Valid(ps.Values[i].String()) {
			return fmt.Errorf("ParameterSet contains non-ASCII characters")
		}
	}

	if nValues == 0 {
		return nil
	}

	typ := ps.ValueType()
	if typ == gems.UndefinedType {
		return fmt.Errorf("ParameterSet contains inconsistent or undefined value types")
	}

	return nil
}

func (ps ParameterSet) String() string {
	var b ascii.Buffer
	ps.MarshalASCII(&b)
	return b.String()
}
