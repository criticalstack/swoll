package syscalls

import (
	"testing"
)

func (dst *Syscall) equals(src *Syscall) bool {
	return dst.Nr == src.Nr &&
		dst.Name == src.Name &&
		dst.Class == src.Class &&
		dst.Group == src.Group
}

func TestSyscalls(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Error(err)
	}

	wants := []Syscall{
		{0, "sys_read", "FileSystem", "ReadWrite"},
	}

	for _, want := range wants {
		has1 := s.Lookup(want.Nr)
		has2 := s.Lookup(want.Name)

		if neq := has1.equals(has2); !neq {
			t.Errorf("lookups did not match for same value: %v/=%v", has1, has2)
		}

		if neq := want.equals(has1); !neq {
			t.Errorf("%v/=%v", want, has1)
		}
	}
}
