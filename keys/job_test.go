package keys

import (
	"testing"
	"time"
)

func TestScheduling(t *testing.T) {
	c := 0
	schedule(time.Second, func() { c++ })
	time.Sleep(time.Second)
	if c == 0 {
		t.Error("Job is not being executed")
	}
}
