package revoke

import (
	"time"
)

type JobFunc func()

func Schedule(interval time.Duration, job JobFunc) {
	go func() {
		for {
			job()
			time.Sleep(interval)
		}
	}()
}
