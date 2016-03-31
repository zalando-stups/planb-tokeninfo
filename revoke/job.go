package revoke

import (
	"time"
)

type JobFunc func()

// Schedule a job (func) to run with a defined time interval between runs.
// Uses a Ticker so if one run of the job takes longer than the interval, the next run will start directly after the
// first. e.g. if the interval is set to 5 seconds and one run takes 6 seconds to complete, the next run will start
// directly after the first (6 seconds) instead of waiting another 5.
func Schedule(interval time.Duration, job JobFunc) {
	go func() {
		for _ = range time.Tick(1 * time.Second) {
			job()
			time.Sleep(interval)
		}
	}()
}
