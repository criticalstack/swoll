//nolint:errcheck
package reader

import (
	"context"
	"testing"
)

type fakeReader struct {
	ch chan interface{}
}

type fakeReaderEvent int

func (f *fakeReader) Read() chan interface{} {
	return f.ch
}

func (f *fakeReader) Run(ctx context.Context) error {
	f.ch <- fakeReaderEvent(1)
	return nil
}

func newfakereader() EventReader {
	r := &fakeReader{make(chan interface{})}

	return r
}

func TestFakeEventReader(t *testing.T) {
	readr := newfakereader()
	go readr.Run(context.TODO())

	msg := <-readr.Read()

	want := 1
	have := msg.(fakeReaderEvent)

	if want != int(have) {
		t.Errorf("want %v, have %v", want, have)
	}
}
