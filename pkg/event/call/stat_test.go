package call

import (
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
)

func TestStat(t *testing.T) {
	s := &Stat{
		Filename: "/tmp/tmux.log",
		StatBuf: syscall.Stat_t{
			Dev:     16,
			Ino:     4,
			Nlink:   20,
			Mode:    0,
			Uid:     2,
			Gid:     5,
			X__pad0: 0,
			Rdev:    16,
			Size:    45679,
			Blksize: 512,
			Blocks:  256,
			Atim: syscall.Timespec{
				Sec:  0,
				Nsec: 0,
			},
			Mtim: syscall.Timespec{
				Sec:  45,
				Nsec: 0,
			},
			Ctim: syscall.Timespec{
				Sec:  22,
				Nsec: 9830002,
			},
			X__unused: [3]int64{28, 98, 72},
		},
	}

	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var a Stat
	if err := json.Unmarshal(j, &a); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Arguments(), a.Arguments()) {
		t.Errorf("Was expecting %v, but got %v\n", s.Arguments(), a.Arguments())

	}
}
