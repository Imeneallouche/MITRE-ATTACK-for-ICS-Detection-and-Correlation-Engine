package gemsV14

import (
	"bytes"
	"fmt"
	"strings"

	gems "github.com/mitre/gems/src"
	"github.com/mitre/gems/src/ascii"
)

var escaper = strings.NewReplacer(
	"&", "&a",
	"|", "&b",
	",", "&c",
	";", "&d",
)

func escape(s string) string {
	return escaper.Replace(s)
}

var unescaper = strings.NewReplacer(
	"&a", "&",
	"&b", "|",
	"&c", ",",
	"&d", ";",
)

func unescape(s string) string {
	return unescaper.Replace(s)
}

func marshalASCIIMessage(b *ascii.Buffer, h MessageHeader, content *ascii.Buffer) error {
	var msg strings.Builder
	fmt.Fprintf(&msg, "%s|", h.transactionID)
	fmt.Fprintf(&msg, "%s|", h.token)
	fmt.Fprintf(&msg, "%s|", h.timestamp)
	fmt.Fprintf(&msg, "%s|", h.target)
	fmt.Fprintf(&msg, "%s", content)
	fmt.Fprint(&msg, "END")

	messageLength := 20 + msg.Len()
	fmt.Fprintf(b, "|GEMS|%s|%010d|%s", asciiVersion, messageLength, msg.String())
	return nil
}

func unmarshalASCIIHeader(data []byte, h *MessageHeader, typ gems.MessageType, minFields int) ([][]byte, error) {
	if err := ascii.Unmarshal(data, h); err != nil {
		return nil, err
	}
	data = bytes.TrimSuffix(data[9:], []byte("|END"))
	fields := bytes.Split(data, []byte{'|'})

	if len(fields) < minFields+6 {
		return nil, &ascii.UnmarshalError{Msg: fmt.Sprintf("incomplete %s message", typ.String())}
	}
	if string(fields[5]) != typ.ASCII() {
		return nil, &ascii.UnmarshalError{Data: fields[5], Msg: fmt.Sprintf("invalid type for %s message", typ.String())}
	}

	return fields[6:], nil
}
