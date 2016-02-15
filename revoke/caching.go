package revoke

import (
	"time"
)

// TODO: make this work
type Cache struct {
	req chan *request
}

type request struct {
	key      string
	value    *Revocation // switch to interface?
	response chan interface{}
}

func NewCache() *Cache {
	req = make(chan *request)

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
