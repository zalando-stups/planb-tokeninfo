package revoke

import (
	"time"
)

type jobFunc func()

func schedule(interval time.Duration, job jobFunc) {
	go func() {
		for {
			job()
			time.Sleep(interval)
		}
	}()
}
