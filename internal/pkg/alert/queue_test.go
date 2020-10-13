package alert

import (
	"fmt"
	"testing"
)

func TestAlertQueue(t *testing.T) {
	alerts := []*Alert{
		{
			Info: Info{
				Status:  StatusFiring,
				Name:    "a1",
				Hash:    "f5dd88504b52de0a",
				Syscall: "sys_connect",
			},
			Source: Source{
				Namespace: "n1",
				Pod:       "p1",
				Container: "c1",
			},
		},
		{
			Info: Info{
				Status:  StatusFiring,
				Name:    "a1",
				Hash:    "8c19e2515f784e90",
				Syscall: "sys_execve",
			},
			Source: Source{
				Namespace: "n1",
				Pod:       "p1",
				Container: "c1",
			},
		},
		{
			Info: Info{
				Status:  StatusResolved,
				Name:    "a1",
				Hash:    "f5dd88504b52de0a",
				Syscall: "sys_connect",
			},
			Source: Source{
				Namespace: "n1",
				Pod:       "p1",
				Container: "c1",
			},
		},
		{
			Info: Info{
				Status:  StatusResolved,
				Name:    "a1",
				Hash:    "8c19e2515f784e90",
				Syscall: "sys_execve",
			},
			Source: Source{
				Namespace: "n1",
				Pod:       "p1",
				Container: "c1",
			},
		},
	}

	queue, err := NewAlertQueue()
	if err != nil {
		t.Fatal(err)
	}

	type tst struct {
		index int
		t     QueueType
		s     *Source
		i     *Info
	}

	wants := []tst{
		{
			index: 0,
			t:     QueueNew,
			s:     &Source{"n1", "p1", "c1"},
			i:     nil,
		},
		{
			index: 0,
			t:     QueueUpdateAdd,
			s:     &Source{"n1", "p1", "c1"},
			i:     &Info{StatusFiring, "a1", "f5dd88504b52de0a", "sys_connect", ""},
		},
		{
			index: 1,
			t:     QueueUpdateAdd,
			s:     &Source{"n1", "p1", "c1"},
			i:     &Info{StatusFiring, "a1", "8c19e2515f784e90", "sys_execve", ""},
		},
		{
			index: 2,
			t:     QueueUpdateDelete,
			s:     &Source{"n1", "p1", "c1"},
			i:     &Info{StatusResolved, "a1", "f5dd88504b52de0a", "sys_connect", ""},
		},
		{
			index: 3,
			t:     QueueUpdateDelete,
			s:     &Source{"n1", "p1", "c1"},
			i:     &Info{StatusResolved, "a1", "8c19e2515f784e90", "sys_execve", ""},
		},
		{
			index: 3,
			t:     QueueDelete,
			s:     &Source{"n1", "p1", "c1"},
			i:     nil,
		},
	}

	haves := []tst{}

	for idx, alert := range alerts {
		err := queue.Push(alert, func(dtype QueueType, src *Source, nfo *Info) {
			fmt.Println(idx, alert)
			haves = append(haves, tst{idx, dtype, src, nfo})
		})
		if err != nil {
			t.Error(err)
		}
	}

	for idx, want := range wants {
		have := haves[idx]
		if have.index != want.index || have.t != want.t {
			t.Errorf("blerp want %v, have %v", want, have)
		}

		haveIsnil := have.s == nil
		wantIsnil := want.s == nil

		if haveIsnil != wantIsnil {
			t.Errorf("source_on want %v, have %v", want, have)
		}

		if have.s != nil && want.s != nil {
			if have.s.Namespace != want.s.Namespace ||
				have.s.Pod != want.s.Pod ||
				have.s.Container != want.s.Container {
				t.Errorf("source want %v, have %v", want, have)
			}
		}

		haveIsnil = have.i == nil
		wantIsnil = want.i == nil

		if haveIsnil != wantIsnil {
			t.Errorf("info_on want %v, have %v", want, have)
		}

		if have.i != nil && want.i != nil {
			if have.i.Status != want.i.Status ||
				have.i.Name != want.i.Name ||
				have.i.Hash != want.i.Hash ||
				have.i.Syscall != want.i.Syscall {
				t.Errorf("info want %v/%v, have %v/%v", want, want.i, have, have.i)
			}
		}
	}

}
