package call

type Setsockopt struct {
	Sockopt
}

func (s *Setsockopt) CallName() string  { return "setsockopt" }
func (s *Setsockopt) Return() *Argument { return nil }

// other interface handlers are defined by Sockopt
