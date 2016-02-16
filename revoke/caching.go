package revoke

import (
	"time"
)

// TODO: make this work
type Cache struct {
	req chan *request
}

type request struct {
	key      map[string]string // not sure if this makes sense; thinking mapping type and hash
	value    *Revocation
	response chan *Revocation
}

func NewCache() *Cache {

	req := make(chan *request)

	go func() {
		m := make(map[string]interface{})

		for {
			select {
			case r := <-req:
				// do something
			}
		}
	}()

	return &Cache{req}
}
