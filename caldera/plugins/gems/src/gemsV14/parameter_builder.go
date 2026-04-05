package gemsV14

import (
	"fmt"

	gems "github.com/mitre/gems/src"
)

type ParameterBuilder struct {
	name         string
	multiplicity gems.NullInt32
	values       ValueSlice
}

func NewParameterBuilder() *ParameterBuilder {
	return &ParameterBuilder{}
}

func (pb *ParameterBuilder) Name(name string) *ParameterBuilder {
	pb.name = name
	return pb
}

func (pb *ParameterBuilder) Multiplicity(i int) *ParameterBuilder {
	pb.multiplicity = gems.NewNullInt32(i)
	return pb
}

func (pb *ParameterBuilder) Parameters(values ...gems.Parameter) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyParameter())
		return pb
	}

	var vs ValueSlice
	for _, v := range values {
		xmlParameter, ok := v.(gems.XMLParameter)
		if !ok {
			continue
		}
		vs = append(vs, xmlParameter)
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) String(values ...string) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyString())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newString(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Boolean(values ...bool) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyBoolean())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newBoolean(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Byte(values ...int) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyByte())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newByte(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Ubyte(values ...int) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyUbyte())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newUbyte(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Short(values ...int) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyShort())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newShort(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Ushort(values ...int) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyUshort())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newUshort(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Int(values ...int) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyInt())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newInt(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Uint(values ...int) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyUint())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newUint(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Long(values ...int) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyLong())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newLong(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Ulong(values ...int) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyUlong())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newUlong(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Double(values ...float64) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyDouble())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newDouble(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) HexValue(values ...string) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyHexValue())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newHexValueFromASCII(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Time(values ...string) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyTimeValue())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newTimeValueFromString(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Utime(values ...string) *ParameterBuilder {
	nVals := len(values)
	if nVals == 0 {
		pb.values = append(pb.values, newEmptyUtime())
		return pb
	}

	vs := make(ValueSlice, nVals)
	for i := range nVals {
		vs[i] = newUtimeFromString(values[i])
	}
	pb.values = vs
	return pb
}

func (pb *ParameterBuilder) Build() (gems.Parameter, error) {
	nValues := len(pb.values)
	vs := make(ValueSlice, nValues)

	valueType := gems.UndefinedType
	for i := range nValues {
		if valueType == gems.UndefinedType {
			valueType = pb.values[i].Type()
		}

		if valueType != pb.values[i].Type() {
			return &ParameterSet{}, fmt.Errorf("build failed: inconsistent value types")
		}

		vs[i] = pb.values[i]
	}

	switch valueType {
	case gems.ParameterSetType:
		p := &ParameterSet{
			name:   pb.name,
			Values: vs,
		}

		if pb.multiplicity.Valid {
			p.Multiplicity = pb.multiplicity
		} else if nValues > 1 {
			p.Multiplicity = gems.NewNullInt32(nValues)
		}
		return p, p.Validate()
	case gems.ParameterType:
		p := &ParameterSet{
			name:   pb.name,
			Values: vs,
		}

		if pb.multiplicity.Valid {
			p.Multiplicity = pb.multiplicity
		}
		return p, p.Validate()

	default:
		p := &Parameter{
			name:   pb.name,
			Values: vs,
		}

		if pb.multiplicity.Valid {
			p.Multiplicity = pb.multiplicity
		} else if nValues > 1 {
			p.Multiplicity = gems.NewNullInt32(nValues)
		}
		return p, p.Validate()
	}
}
