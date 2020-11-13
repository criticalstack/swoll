package call

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Argument represents a single value within a function call.
// function(arg=(int)N <- name="arg", type="int", value="N"
type Argument struct {
	// the name of the Value
	Name string `json:"name"`
	// the Type of the Value
	Type string `json:"type"`
	// THE ACTUAL VALUE OF THE VALUE!
	Value interface{} `json:"val"`
}

type Arguments []*Argument

// Function represents a function call of some sort,
// as of the time of writing, that's just syscalls.
type Function interface {
	// The name of the function
	CallName() string
	// The return argument of the function
	Return() *Argument
	// A slight abstraction around function arguments and how they can
	// be semi-serialized. This must return an array of EventArg's
	Arguments() Arguments
	// TODO[lz]: uhh, maybe one day, this just seems like
	// more work than needed, and little to no use, right?
	// Marshal() ([]byte, error)
}

// FunctionDecoder api's should be able to read in an array of byte pointers
// (basically void argv[][]), and fill in information about itself.
type FunctionDecoder interface {
	DecodeArguments([]*byte, int) error
}

// Functionhandler api's define a function they are authoratative for, and a
// decoder for the function.
type FunctionHandler interface {
	Function
	FunctionDecoder
}

// FunctionHandle allows for abstract readers/writers on handlers.
type FunctionHandle struct {
	FunctionHandler
}

func (a Argument) String() string {
	return fmt.Sprintf("%s=(%s)%v", a.Name, a.Type, a.Value)
}

func (a Argument) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"name": a.Name,
		"type": a.Type,
		"val":  a.Value},
	)
}

func (a Arguments) String() string {
	args := make([]string, 0, len(a))

	for _, arg := range a {
		args = append(args, arg.String())
	}

	return strings.Join(args, ", ")
}

func (h *FunctionHandle) String() string {
	if ret := h.Return(); ret != nil {
		return fmt.Sprintf("%s(%s)=%v", h.CallName(), h.Arguments(), ret)
	}

	return fmt.Sprintf("%s(%s)", h.CallName(), h.Arguments())
}

func (h *FunctionHandle) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"name": h.CallName(),
		"args": h.Arguments(),
		"ret":  h.Return(),
	})
}
