package goxml

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
)

type Werror struct {
	P     []string // err msgs for public consumption
	C     []string
	PC    []uintptr `json:"-"`
	Cause error
	Xp    *Xp `json:"-"`
}

// NewWerror allows us to make error that are list of semistructured messages "tag: message" to
// allow for textual error messages that can be interpreted by a program.
func NewWerror(ctx ...string) Werror {
	x := Werror{C: ctx}
	x.PC = make([]uintptr, 32)
	n := runtime.Callers(2, x.PC)
	x.PC = x.PC[:n]
	return x
}

// Wrap a std error in a Werror
func Wrap(err error, ctx ...string) Werror {
	switch x := err.(type) {
	case Werror:
		x.C = append(x.C, ctx...)
		return x
	default:
		werr := NewWerror("cause:" + err.Error())
		werr.Cause = err
		return Wrap(werr, ctx...)
	}
}

// WrapWithXp - keep the Xp to be able to debug
func WrapWithXp(err error, xp *Xp, ctx ...string) error {
	werr := Wrap(err, ctx...)
	werr.Xp = xp
	return werr
}

// PublicError - append messages to a Werror
func PublicError(e Werror, ctx ...string) error {
	e.P = append(e.P, ctx...)
	return e
}

// Error downgrade an Werror to error
func (e Werror) Error() (err string) {
	errjson, _ := json.Marshal(e.C)
	if len(e.P) > 0 {
		errjson, _ = json.Marshal(e.P)
	}
	err = string(errjson)
	return
}

// FullError - convert to JSON
func (e Werror) FullError() (err string) {
	errjson, _ := json.Marshal(append(e.C, e.P...))
	err = string(errjson)
	return
}

// Stack - get stack as string
func (e Werror) Stack(depth int) (st string) {
	n := len(e.PC)
	if n > 0 && depth < n {
		pcs := e.PC[:n-depth]
		frames := runtime.CallersFrames(pcs)
		for {
			frame, more := frames.Next()
			function := frame.Function
			file := strings.Split(frame.File, "/")
			st += fmt.Sprintf(" %s %s %d\n", function, file[len(file)-1:][0], frame.Line)
			if !more {
				break
			}
		}
	}
	return
}
