package keys

import (
	"testing"
	"time"
)

func TestScheduling(t *testing.T) {
	c := 0
	schedule(time.Millisecond, func() { c++ })
	time.Sleep(time.Millisecond * 2)
	if c == 0 {
		t.Error("Job is not being executed")
	}
}
