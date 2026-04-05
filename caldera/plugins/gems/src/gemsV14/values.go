package gemsV14

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	gems "github.com/mitre/gems/src"
	"github.com/mitre/gems/src/ascii"
)

type ValueSlice []gems.XMLValue

func (vs ValueSlice) MarshalASCII(b *ascii.Buffer) error {
	var err error
	for i, v := range vs {
		switch v.Type() {
		case gems.ParameterSetType:
			ps, ok := v.(*ParameterSet)
			if !ok {
				return fmt.Errorf("error marshaling parameter set")
			}
			err = ps.Values.MarshalASCII(b)
		default:
			err = v.MarshalASCII(b)
		}
		if err != nil {
			return err
		}

		switch v.Type() {
		case gems.ParameterType:
			b.WriteRune(';')
		default:
			if i < len(vs)-1 {
				b.WriteRune(',')
			}
		}
	}

	return nil
}

func (vs *ValueSlice) unmarshalASCII(splitData [][]byte, typ gems.Datatype) error {
	if vs == nil {
		return fmt.Errorf("ValueSlice is nil")
	}
	for _, d := range splitData {
		v, err := newValue(typ)
		if err != nil {
			return err
		}
		if err := ascii.Unmarshal(d, v); err != nil {
			return err
		}
		*vs = append(*vs, v)
	}
	return nil
}

func newValue(typ gems.Datatype) (gems.XMLValue, error) {
	switch typ {
	case gems.StringType:
		return newEmptyString(), nil
	case gems.BooleanType:
		return newEmptyBoolean(), nil
	case gems.ByteType:
		return newEmptyByte(), nil
	case gems.UbyteType:
		return newEmptyUbyte(), nil
	case gems.ShortType:
		return newEmptyShort(), nil
	case gems.UshortType:
		return newEmptyUshort(), nil
	case gems.IntType:
		return newEmptyInt(), nil
	case gems.UintType:
		return newEmptyUint(), nil
	case gems.LongType:
		return newEmptyLong(), nil
	case gems.UlongType:
		return newEmptyUlong(), nil
	case gems.DoubleType:
		return newEmptyDouble(), nil
	case gems.HexValueType:
		return newEmptyHexValue(), nil
	case gems.TimeType:
		return newEmptyTimeValue(), nil
	case gems.UtimeType:
		return newEmptyUtime(), nil
	case gems.ParameterType:
		return newEmptyParameter(), nil
	case gems.ParameterSetType:
		return newEmptyParameterSet(), nil
	default:
		return nil, fmt.Errorf("unexpected type '%s'", typ)
	}
}

type String struct {
	Data  string
	Empty bool
}

func newString(value string) *String {
	v := String{Data: value}
	return &v
}

func newEmptyString() *String {
	v := String{Empty: true}
	return &v
}

func (v String) Type() gems.Datatype {
	return gems.StringType
}

func (v String) String() string {
	return v.Data
}

func (v String) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *String) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}

	if content == "" {
		v.Empty = true
		return nil
	}
	v.Empty = false
	v.Data = content
	return nil
}

func (v String) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}

	return b.SafeWrite(escape(v.String()))
}

func (v *String) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	v.Empty = false
	v.Data = unescape(string(data))
	return nil
}

type Boolean struct {
	Data  bool
	Empty bool
}

func newBoolean(value bool) *Boolean {
	v := Boolean{Data: value}
	return &v
}

func newEmptyBoolean() *Boolean {
	v := Boolean{Empty: true}
	return &v
}

func (v Boolean) Type() gems.Datatype {
	return gems.BooleanType
}

func (v Boolean) String() string {
	if v.Empty {
		return ""
	}
	return strconv.FormatBool(v.Data)
}

func (v Boolean) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Boolean) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var (
		content string
		err     error
	)
	if err = d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}
	v.Empty = false
	v.Data, err = strconv.ParseBool(content)
	return err
}

func (v Boolean) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

func (v *Boolean) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	var err error
	v.Data, err = strconv.ParseBool(string(data))
	v.Empty = false
	return err
}

type Byte struct {
	Data  int8
	Empty bool
}

func newByte(value int) *Byte {
	if value > math.MaxInt8 {
		value = math.MaxInt8
	}
	v := Byte{Data: int8(value)}
	return &v
}

func newEmptyByte() *Byte {
	v := Byte{Empty: true}
	return &v
}

func (v Byte) Type() gems.Datatype {
	return gems.ByteType
}

func (v Byte) String() string {
	if v.Empty {
		return ""
	}
	return strconv.FormatInt(int64(v.Data), 10)
}

func (v Byte) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Byte) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseInt(content, 10, 8)
	if err != nil {
		return err
	}
	v.Data = int8(i)
	v.Empty = false
	return nil
}

func (v Byte) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

func (v *Byte) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseInt(string(data), 10, 8)
	if err != nil {
		return err
	}
	v.Data = int8(i)
	v.Empty = false
	return nil
}

type Ubyte struct {
	Data  uint8
	Empty bool
}

func newUbyte(value int) *Ubyte {
	if value > math.MaxUint8 {
		value = math.MaxUint8
	}
	v := Ubyte{Data: uint8(value)}
	return &v
}

func newEmptyUbyte() *Ubyte {
	v := Ubyte{Empty: true}
	return &v
}

func (v Ubyte) Type() gems.Datatype {
	return gems.UbyteType
}

func (v Ubyte) String() string {
	if v.Empty {
		return ""
	}
	return strconv.FormatUint(uint64(v.Data), 10)
}

func (v Ubyte) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Ubyte) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseUint(content, 10, 8)
	if err != nil {
		return err
	}
	v.Data = uint8(i)
	v.Empty = false
	return nil
}

func (v Ubyte) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

func (v *Ubyte) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseUint(string(data), 10, 8)
	if err != nil {
		return err
	}
	v.Data = uint8(i)
	v.Empty = false
	return nil
}

type Long struct {
	Data  int64
	Empty bool
}

func newLong(value int) *Long {
	v := Long{Data: int64(value)}
	return &v
}

func newEmptyLong() *Long {
	v := Long{Empty: true}
	return &v
}

func (v Long) Type() gems.Datatype {
	return gems.LongType
}

func (v Long) String() string {
	if v.Empty {
		return ""
	}
	return strconv.FormatInt(v.Data, 10)
}

func (v Long) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Long) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseInt(content, 10, 64)
	if err != nil {
		return err
	}
	v.Data = i
	v.Empty = false
	return nil
}

func (v Long) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

func (v *Long) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err
	}
	v.Data = i
	v.Empty = false
	return nil
}

type Ulong struct {
	Data  uint64
	Empty bool
}

func newUlong(value int) *Ulong {
	v := Ulong{Data: uint64(value)}
	return &v
}

func newEmptyUlong() *Ulong {
	v := Ulong{Empty: true}
	return &v
}

func (v Ulong) Type() gems.Datatype {
	return gems.UlongType
}

func (v Ulong) String() string {
	if v.Empty {
		return ""
	}
	return strconv.FormatUint(v.Data, 10)
}

func (v Ulong) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Ulong) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseUint(content, 10, 64)
	if err != nil {
		return err
	}
	v.Data = i
	v.Empty = false
	return nil
}

func (v *Ulong) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseUint(string(data), 10, 64)
	if err != nil {
		return err
	}
	v.Data = i
	v.Empty = false
	return nil
}

func (v Ulong) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

type Int struct {
	Data  int32
	Empty bool
}

func newInt(value int) *Int {
	if value > math.MaxInt32 {
		value = math.MaxInt32
	}
	v := Int{Data: int32(value)}
	return &v
}

func newEmptyInt() *Int {
	v := Int{Empty: true}
	return &v
}

func (v Int) Type() gems.Datatype {
	return gems.IntType
}

func (v Int) String() string {
	if v.Empty {
		return ""
	}
	return strconv.FormatInt(int64(v.Data), 10)
}

func (v Int) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Int) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseInt(content, 10, 32)
	if err != nil {
		return err
	}
	v.Data = int32(i)
	v.Empty = false
	return nil
}

func (v Int) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

func (v *Int) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseInt(string(data), 10, 32)
	if err != nil {
		return err
	}
	v.Data = int32(i)
	v.Empty = false
	return nil
}

type Uint struct {
	Data  uint32
	Empty bool
}

func newUint(value int) *Uint {
	if value > math.MaxUint32 {
		value = math.MaxUint32
	}
	v := Uint{Data: uint32(value)}
	return &v
}

func newEmptyUint() *Uint {
	v := Uint{Empty: true}
	return &v
}

func (v Uint) Type() gems.Datatype {
	return gems.UintType
}

func (v Uint) String() string {
	if v.Empty {
		return ""
	}
	return strconv.FormatUint(uint64(v.Data), 10)
}

func (v Uint) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Uint) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseUint(content, 10, 32)
	if err != nil {
		return err
	}
	v.Data = uint32(i)
	v.Empty = false
	return nil
}

func (v Uint) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

func (v *Uint) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseUint(string(data), 10, 32)
	if err != nil {
		return err
	}
	v.Data = uint32(i)
	v.Empty = false
	return nil
}

type Short struct {
	Data  int16
	Empty bool
}

func newShort(value int) *Short {
	if value > math.MaxInt16 {
		value = math.MaxInt16
	}
	v := Short{Data: int16(value)}
	return &v
}

func newEmptyShort() *Short {
	v := Short{Empty: true}
	return &v
}

func (v Short) Type() gems.Datatype {
	return gems.ShortType
}

func (v Short) String() string {
	if v.Empty {
		return ""
	}
	return strconv.FormatInt(int64(v.Data), 10)
}

func (v Short) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Short) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseInt(content, 10, 16)
	if err != nil {
		return err
	}
	v.Data = int16(i)
	v.Empty = false
	return nil
}

func (v Short) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

func (v *Short) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseInt(string(data), 10, 16)
	if err != nil {
		return err
	}
	v.Data = int16(i)
	v.Empty = false
	return nil
}

type Ushort struct {
	Data  uint16
	Empty bool
}

func newUshort(value int) *Ushort {
	if value > math.MaxUint16 {
		value = math.MaxUint16
	}
	v := Ushort{Data: uint16(value)}
	return &v
}

func newEmptyUshort() *Ushort {
	v := Ushort{Empty: true}
	return &v
}

func (v Ushort) Type() gems.Datatype {
	return gems.UshortType
}

func (v Ushort) String() string {
	if v.Empty {
		return ""
	}
	return strconv.FormatUint(uint64(v.Data), 10)
}

func (v Ushort) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Ushort) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseUint(content, 10, 16)
	if err != nil {
		return err
	}
	v.Data = uint16(i)
	v.Empty = false
	return nil
}

func (v Ushort) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

func (v *Ushort) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseUint(string(data), 10, 16)
	if err != nil {
		return err
	}
	v.Data = uint16(i)
	v.Empty = false
	return nil
}

type Double struct {
	Data  float64
	Empty bool
}

func newDouble(value float64) *Double {
	v := Double{Data: value}
	return &v
}

func newEmptyDouble() *Double {
	v := Double{Empty: true}
	return &v
}

func (v Double) Type() gems.Datatype {
	return gems.DoubleType
}

func (v Double) String() string {
	if v.Empty {
		return ""
	}
	return strconv.FormatFloat(float64(v.Data), 'f', -1, 64)
}

func (v Double) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Double) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseFloat(content, 64)
	if err != nil {
		return err
	}
	v.Data = i
	v.Empty = false
	return nil
}

func (v Double) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

func (v *Double) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	i, err := strconv.ParseFloat(string(data), 64)
	if err != nil {
		return err
	}
	v.Data = i
	v.Empty = false
	return nil
}

type HexValue struct {
	Data      []byte
	BitLength int
	Empty     bool
}

func newHexValue(value []byte, bitLength int) *HexValue {
	if bitLength == 0 {
		bitLength = hex.EncodedLen(len(value))
	}
	v := HexValue{Data: value, BitLength: bitLength}
	return &v
}

// newHexValueFromStream returns the HexValue represented by the
// hexadecimal string value.
// newHexValueFromStream expects that value contains only hexadecimal characters
// and that value has even length. If the input is malformed, the resulting HexValue
// contains the bytes decoded before the error.
func newHexValueFromStream(value string, bitLength int) *HexValue {
	decoded, _ := hex.DecodeString(value)
	if bitLength == 0 {
		bitLength = hex.EncodedLen(len(decoded))
	}
	v := HexValue{Data: decoded, BitLength: bitLength}
	return &v
}

func newHexValueFromASCII(value string) *HexValue {
	if len(value) == 0 {
		return newEmptyHexValue()
	}

	var v HexValue
	if err := ascii.Unmarshal([]byte(value), &v); err != nil {
		return newEmptyHexValue()
	}
	return &v
}

func newEmptyHexValue() *HexValue {
	v := HexValue{Empty: true}
	return &v
}

func (v HexValue) Type() gems.Datatype {
	return gems.HexValueType
}

func (v HexValue) String() string {
	encodedLen := hex.EncodedLen(len(v.Data))
	if v.BitLength < encodedLen {
		v.BitLength = encodedLen
	}

	if v.Empty || (v.BitLength == 0) {
		return "0/0"
	}
	dst := make([]byte, encodedLen)
	hex.Encode(dst, v.Data)
	hexStream := strings.ToUpper(string(dst))
	return hexStream
}

func (v HexValue) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	hexStream := v.String()

	bitLengthAttr := xml.Attr{
		Name:  xml.Name{Local: "bit_length"},
		Value: strconv.FormatInt(int64(v.BitLength), 10),
	}
	start.Attr = append(start.Attr, bitLengthAttr)
	return e.EncodeElement(hexStream, start)
}

func (v *HexValue) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var err error
	for _, attr := range start.Attr {
		if attr.Name.Local == "bit_length" {
			if v.BitLength, err = strconv.Atoi(attr.Value); err != nil {
				return err
			}
		}

	}

	if v.BitLength == 0 {
		v.Empty = true
		return nil
	}

	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}

	if v.Data, err = hex.DecodeString(content); err != nil {
		return err
	}
	v.Empty = false
	return nil
}

func (v HexValue) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	if v.BitLength == 0 {
		_, err := b.WriteString("0/0")
		return err
	}
	_, err := fmt.Fprintf(b, "%s/%d", v, v.BitLength)
	return err
}

func (v *HexValue) UnmarshalASCII(data []byte) error {
	if (len(data) == 0) || (string(data) == "0/0") {
		v.Empty = true
		return nil
	}
	valueStr, bitLengthStr, found := strings.Cut(string(data), "/")
	if !found {
		return &ascii.UnmarshalError{Data: data, Msg: "HexValue missing '/' separator"}
	}

	var err error
	if v.BitLength, err = strconv.Atoi(bitLengthStr); err != nil {
		return err
	}

	valueStr = strings.ToUpper(valueStr)
	valueStr = strings.TrimPrefix(valueStr, "0X")
	v.Data, err = hex.DecodeString(valueStr)
	v.Empty = false
	return err
}

type Time struct {
	Data  gems.Time
	Empty bool
}

func newTimeValue(value time.Time) *Time {
	v := Time{Data: gems.Time{Time: value}}
	return &v
}

func newTimeValueFromString(value string) *Time {
	t, err := gems.TimeFromString(value)
	if err != nil {
		return newEmptyTimeValue()
	}
	v := Time{Data: t}
	return &v
}

func newEmptyTimeValue() *Time {
	v := Time{Empty: true}
	return &v
}

func (v Time) Type() gems.Datatype {
	return gems.TimeType
}

func (v Time) String() string {
	if v.Empty {
		return ""
	}
	return v.Data.FormatTime()
}

func (v Time) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Time) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var (
		content string
		err     error
	)
	if err = d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}

	v.Empty = false
	v.Data, err = gems.TimeFromString(content)
	return err
}

func (v Time) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

func (v *Time) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	var err error
	v.Data, err = gems.TimeFromString(string(data))
	v.Empty = false
	return err
}

type Utime struct {
	Data  gems.Time
	Empty bool
}

func newUtime(value time.Time) *Utime {
	v := Utime{Data: gems.Time{Time: value}}
	return &v
}

func newUtimeFromString(value string) *Utime {
	t, err := gems.TimeFromUtime(value)
	if err != nil {
		return newEmptyUtime()
	}
	v := Utime{Data: t}
	return &v
}

func newEmptyUtime() *Utime {
	v := Utime{Empty: true}
	return &v
}

func (v Utime) Type() gems.Datatype {
	return gems.UtimeType
}

func (v Utime) String() string {
	if v.Empty {
		return ""
	}
	return v.Data.FormatUtime()
}

func (v Utime) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = v.Type().XMLName()
	return e.EncodeElement(v.String(), start)
}

func (v *Utime) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var (
		content string
		err     error
	)
	if err = d.DecodeElement(&content, &start); err != nil {
		return err
	}
	if content == "" {
		v.Empty = true
		return nil
	}

	v.Empty = false
	v.Data, err = gems.TimeFromUtime(content)
	return err
}

func (v Utime) MarshalASCII(b *ascii.Buffer) error {
	if v.Empty {
		return nil
	}
	_, err := b.WriteString(v.String())
	return err
}

func (v *Utime) UnmarshalASCII(data []byte) error {
	if len(data) == 0 {
		v.Empty = true
		return nil
	}
	var err error
	v.Data, err = gems.TimeFromUtime(string(data))
	v.Empty = false
	return err
}
