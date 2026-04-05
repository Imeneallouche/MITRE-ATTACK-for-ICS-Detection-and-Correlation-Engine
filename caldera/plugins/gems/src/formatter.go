package gems

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

type MessageFormatter interface {
	Format(Message) string
}

type DefaultFormatter struct{}

func (p DefaultFormatter) Format(msg Message) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s | %s | '%s' | %s |", msg.Type(), msg.TransactionID(), msg.Token(), msg.Target())

	out, err := json.MarshalIndent(msg.Body(), "", "  ")
	if (err != nil) || (len(msg.Body()) == 0) {
		return b.String()
	}

	b.WriteRune('\n')
	b.Write(out)
	return b.String()
}

type ResponseContentFormatter struct{}

func (p ResponseContentFormatter) Format(msg Message) string {
	var b strings.Builder
	b.WriteString(msg.Type().String())

	if m, ok := msg.(Response); ok {
		fmt.Fprintf(&b, ", %s\n", m.Result())

		body := msg.Body()
		for key, value := range body {
			switch key {
			case "result_code", "result_description":
				continue
			case "parameters", "configurations", "arguments", "return_values":
				fmt.Fprintf(&b, "%s:\n", key)
				val := reflect.ValueOf(value)
				if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
					for i := range val.Len() {
						fmt.Fprintf(&b, "  %v\n", val.Index(i).Interface())
					}
				}
			default:
				fmt.Fprintf(&b, "%s: %v\n", key, value)
			}
		}
	}

	s := b.String()
	s = strings.TrimSuffix(s, "\n")
	return s
}

type BodyFormatter struct{}

func (b BodyFormatter) Format(msg Message) string {
	out, err := json.MarshalIndent(msg.Body(), "", "  ")
	if err != nil {
		return ""
	}
	return string(out)
}
