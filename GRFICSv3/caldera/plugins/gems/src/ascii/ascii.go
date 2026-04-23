package ascii

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
)

func SplitMessages(data []byte, atEOF bool) (advance int, token []byte, err error) {
	delimiter := []byte("|END")
	if i := bytes.Index(data, delimiter); i >= 0 {
		endIdx := i + len(delimiter)
		return endIdx, data[:endIdx], nil
	}
	if atEOF && len(data) > 0 {
		return 0, nil, fmt.Errorf("received partial GEMS-ASCII message")
	}
	if atEOF {
		return 0, nil, io.EOF
	}
	return 0, nil, nil
}

// Marshal returns the GEMS-ASCII encoding of v.
func Marshal(v Marshaler) ([]byte, error) {
	b := &Buffer{}

	if v == nil {
		return b.Bytes(), nil
	}

	err := v.MarshalASCII(b)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Buffer stores GEMS-ASCII into a bytes.Buffer.
type Buffer struct {
	bytes.Buffer
}

// Marshaler is implemented by types that can
// marshal themselves in to valid GEMS-ASCII
type Marshaler interface {
	MarshalASCII(b *Buffer) error
}

type MarshalError struct {
	Msg string
}

func (e *MarshalError) Error() string {
	return fmt.Sprintf("gems-ascii: marshal failed, %s", e.Msg)
}

var escaperV01 = strings.NewReplacer(
	"|", "/|",
	",", "/,",
)

var escaperV02 = strings.NewReplacer(
	"&", "&a",
	"|", "&b",
	",", "&c",
	";", "&d",
)

func Valid(val string) bool {
	for _, c := range val {
		if c > 127 {
			return false
		}
	}
	return true
}

// SafeWrite writes user-controlled data to the buffer.
//
// SafeWrite conducts the following verification of user
// data:
// 1. Return error if reserved word is used.
// 2. Return error if a non-ASCII character is used.
// Escaping of reserved characters is left to the individual
// version packages as the escape methodology has changed.
// Following successful validation, data is written to the buffer.
func (b *Buffer) SafeWrite(val string) error {
	if val == "|GEMS" || val == "|END|" {
		return &MarshalError{Msg: fmt.Sprintf("use of reserved word '%s'", val)}
	}
	if !Valid(val) {
		return &MarshalError{Msg: fmt.Sprintf("unable to encode non-ASCII characters in '%s'", val)}
	}

	_, err := b.WriteString(val)
	return err
}

// Unmarshal parses GEMS-ASCII data and stores the result in
// the value pointed to by v.
func Unmarshal(data []byte, v any) error {
	val := reflect.ValueOf(v)

	// Dereference interface and pointer types
	for (val.Kind() == reflect.Interface || val.Kind() == reflect.Pointer) && !val.IsNil() {
		val = val.Elem()
	}

	// Ensure the value is addressable and create a new instance if it's a nil pointer
	if val.Kind() == reflect.Pointer && val.IsNil() {
		val.Set(reflect.New(val.Type().Elem()))
		val = val.Elem()
	}

	var (
		unmarshaler Unmarshaler
		ok          bool
	)

	if val.CanInterface() {
		unmarshaler, ok = val.Interface().(Unmarshaler)
	}

	if val.CanAddr() {
		unmarshaler, ok = val.Addr().Interface().(Unmarshaler)
	}

	if !ok {
		return &UnmarshalError{Msg: "failed to cast value as Unmarshaler"}
	}
	return unmarshaler.UnmarshalASCII(data)
}

// Unmarshaler is implemented by types
// that can unmarshal a GEMS-ASCII encoding of
// themselves.
type Unmarshaler interface {
	UnmarshalASCII([]byte) error
}

var asciiUnmarshalerType = reflect.TypeOf((*Unmarshaler)(nil)).Elem()

type UnmarshalError struct {
	Data []byte
	Msg  string
}

func (e *UnmarshalError) Error() string {
	if e.Data != nil {
		return fmt.Sprintf("gems-ascii: unmarshal of '%s' failed, %s", e.Data, e.Msg)
	}
	return fmt.Sprintf("gems-ascii: unmarshal failed, %s", e.Msg)
}

var unescaperV01 = strings.NewReplacer(
	"/|", "|",
	"/,", ",",
)

var unescaperV02 = strings.NewReplacer(
	"&a", "&",
	"&b", "|",
	"&c", ",",
	"&d", ";",
)
