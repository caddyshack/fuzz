// Copyright 2014 Matt T. Proud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fuzz provides blackbox testing helpers for the testing/quick package
// or your own implementation.
package fuzz

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"testing/quick"
)

var (
	errIllegal          = errors.New("fuzz: illegal type for quick.Value")
	errMissingFunc      = errors.New("fuzz: missing assigned generator")
	errNotStruct        = errors.New("fuzz: requested type is not a struct")
	errUnmatchedBinding = errors.New("fuzz: unmatched binding")
	errDuplBinding      = errors.New("fuzz: duplicated binding")
	errIllegalGen       = errors.New("fuzz: illegal generator")
)

// Fuzz describes a context in which a given struct's fields are to be
// annotated.
type Fuzz struct {
	bindings             map[string]Generator
	zeroValueFallthrough bool
	typ                  reflect.Type
	fields map[string]reflect.StructField
}

type option func(*Fuzz) (option, error)

// Option applies a setting to the Fuzz session, returning an option that may be
// applied to revert the current operation.  If an error occurs while applying the
// options, the operation short circuits.
func (f *Fuzz) Option(opts ...option) (prev option, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if err, ok = r.(error); ok {
			} else {
				err = fmt.Errorf("fuzz: option error %s", r)
			}
		}
	}()
	for _, opt := range opts {
		prev, err = opt(f)
		if err != nil {
			return prev, err
		}
	}
	return prev, err
}

func (f *Fuzz) MustOption(opts ...option)  option {
	prev, err := f.Option(opts...)
	if err != nil {
		panic(err)
	}
	return prev
}

// UseZeroValueFallthrough instructs the session to use the zero-value for
// all unbound fields; otherwise, a random value is chosen.
func UseZeroValueFallthrough(on bool) option {
	return func(f *Fuzz) (option, error) {
		prev := f.zeroValueFallthrough
		f.zeroValueFallthrough = on
		return UseZeroValueFallthrough(prev), nil
	}
}

// BindField attaches a generator to a named field.
func BindField(name string, gen Generator) option {
	return func(f *Fuzz) (option, error) {
		if _, ok := f.bindings[name]; ok {
			return nil, errDuplBinding
		}
		if _, ok := f.fields[name]; !ok {
			return nil, errUnmatchedBinding
		}
		f.bindings[name] = gen
		return UnbindField(name), nil
	}
}

// UnbindField removes a generator from a named field.
func UnbindField(name string) option {
	return func(f *Fuzz) (option, error) {
		gen, ok := f.bindings[name]
		if !ok {
			return nil, fmt.Errorf("fuzz: absent binding %s", name)
		}
		delete(f.bindings, name)
		return BindField(name, gen), nil
	}
}

// Value emits a Value for the requested session.
func (f *Fuzz) Value(r *rand.Rand, n int) (v reflect.Value, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if err, ok = r.(error); ok {
			} else {
				err = fmt.Errorf("fuzz: %v", r)
			}
		}
	}()
	v = reflect.New(f.typ).Elem()
	for name, field := range f.fields {
		gen, ok := f.bindings[name]
		switch {
		case ok:
			elem, err := gen.Generate(r, n)
			if err != nil {
				return v, err
			}
			v.FieldByName(name).Set(elem)
		case f.zeroValueFallthrough:
			continue
		default:
			elem, ok := quick.Value(field.Type, r)
			if !ok {
				return v, errIllegal
			}
			v.FieldByName(name).Set(elem)
		}
	}
	return v, err
}

// New generates a new Fuzz session for type t, which must be a struct.
func New(t reflect.Type) (*Fuzz, error) {
	if t == nil || t.Kind() != reflect.Struct {
		return nil, errNotStruct
	}
	fields := make(map[string]reflect.StructField)
	for i := 0; i < t.NumField(); i++ {
		fields[t.Field(i).Name] = t.Field(i)
	}
	return &Fuzz{typ: t, bindings: make(map[string]Generator), fields: fields}, nil
}

// Must wraps New invocations to ensure that errors are caught at initialization
// time.
func Must(f *Fuzz, e error) *Fuzz {
	if e != nil {
		panic(e)
	}
	return f
}

type quickGeneratorFunc func(rand *rand.Rand, n int) (reflect.Value, error)

func (f quickGeneratorFunc) Generate(r *rand.Rand, n int) reflect.Value {
	v, err := f(r, n)
	if err != nil {
		panic(fmt.Errorf("fuzz: %s", err))
	}
	return v
}

// QuickGenerator type is an adaptor to allow the use of Generator as
// testing/quick's Generator.  It panics if the underlying Generator
// emits an error.
func QuickGenerator(g Generator) quick.Generator {
	return quickGeneratorFunc(g.Generate)
}

// The QuickValues type is an adaptor to allow the use of Generator as
// testing/quick's Config.Values.  It panics if an error occurs in the
// stack.
func QuickValues(g ...Generator) func([]reflect.Value, *rand.Rand) {
	return func(v []reflect.Value, r *rand.Rand) {
		if len(v) != len(v) {
			panic("fuzz: incongruent Values() and Generator... signature")
		}
		for i, g := range g {
			var err error
			v[i], err = g.Generate(r, 0)
			if err != nil {
				panic(fmt.Errorf("fuzz: %s", err))
			}
		}
	}
}

// Generator creates types per a user-provided policy.
type Generator interface {
	// Generate emits a generated value for the provided random r and size hint n.
	Generate(r *rand.Rand, n int) (reflect.Value, error)
}

// The GeneratorFunc type is an adaptor to allow the use of ordinary functions
// value generators.
type GeneratorFunc func(rand *rand.Rand, n int) (reflect.Value, error)

func (g GeneratorFunc) Generate(rand *rand.Rand, size int) (reflect.Value, error) {
	return g(rand, size)
}
