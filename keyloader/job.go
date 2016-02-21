package keyloader

import "time"

// JobFunc is a type that defines a zero argument function
type JobFunc func()

// Schedule executes the job in regular intervals. The task is left running in the background
func Schedule(interval time.Duration, job JobFunc) {
	go func() {
		for {
			job()
			time.Sleep(interval)
		}
	}()
}
