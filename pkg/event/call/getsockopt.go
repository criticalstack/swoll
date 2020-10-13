package call

type Getsockopt struct {
	Sockopt `json:"sockopt"`
}

func (g *Getsockopt) CallName() string  { return "getsockopt" }
func (g *Getsockopt) Return() *Argument { return nil }

// other interface handlers are defined by Sockopt
