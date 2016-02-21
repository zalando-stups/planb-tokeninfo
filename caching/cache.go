/*
Package caching implements a thread safe cache with string keys

	Usage:

	Create a new cache instance with the NewCache() function

		c := caching.NewCache()

	This creates a new cache, backed by a map[string]interface{}

	You can then set values for arbitrary keys with the Set() function for later retrieval with
	the Get() function

		c.Set("key1", "value1")
		...
		if v := c.Get("key1"); v != nil {
			doSomethingWith(v) // Do something with "value1"
		}

	When necessary, it's necessary to get a snapshot of the cache. This is done with the
	Snapshot() function

		s := c.Snapshot()
		if v, has := s["key1"]; has {
			doSomethingWith(v)
		}

	Caches can be reset and cleared. Both operations return the previous cache content.

	Reset can replace the cache content with a new map[string]interface{}.

		m := map[string]interface{}{"key2":"value2"}
		old := c.Reset(m)
		if v := c.Get("key2"); v != nil {
			doSomethingWith(v) // Do something with "value2"
		}

	Clear empties the content of the cache entirely.

		s1 := c.Snapshot() // map with some key/value pairs
		c.Clear()
		s2 := c.Snapshot() // s2 is an empty map
*/
package caching

// Cache type holds the channels used for thread safe operations with the internal data structure
type Cache struct {
	req  chan *request
	quit chan struct{}
}

type operation int

type request struct {
	op       operation
	key      string
	value    interface{}
	response chan interface{}
}

const (
	get operation = iota
	set
	del
	clear
	reset
	snapshot
)

// NewCache creates a new map that can be used to cache key/value pairs in a highly concurrent environment.
// It is thread safe in all of its operations
func NewCache() *Cache {
	req := make(chan *request)
	quit := make(chan struct{})

	go func() {
		m := make(map[string]interface{})

		for {
			select {
			case r := <-req:
				r.response <- doOp(&m, r)
			case <-quit:
				return
			}

		}
	}()

	return &Cache{req, quit}
}

func doOp(m *map[string]interface{}, r *request) interface{} {
	switch r.op {
	case set:
		old := (*m)[r.key]
		(*m)[r.key] = r.value
		return old
	case get:
		return (*m)[r.key]
	case del:
		old := (*m)[r.key]
		delete(*m, r.key)
		return old
	case clear:
		oldMap := *m
		*m = make(map[string]interface{})
		return oldMap
	case reset:
		oldMap := *m
		*m = r.value.(map[string]interface{})
		return oldMap
	case snapshot:
		newMap := make(map[string]interface{})
		for k, v := range *m {
			newMap[k] = v
		}
		return newMap
	default:
		panic("Unsupported cache operation")
	}
}

// Get looks up the key in the cache and returns nil if it's not found
func (c *Cache) Get(key string) interface{} {
	response := make(chan interface{})
	c.req <- &request{key: key, response: response, op: get}
	return <-response
}

// Set stores value for the key in the cache and returns any previous value for key
func (c *Cache) Set(key string, value interface{}) interface{} {
	response := make(chan interface{})
	c.req <- &request{key: key, value: value, response: response, op: set}
	return <-response
}

// Delete removes the key from the cache and returns any previous value set for that key
func (c *Cache) Delete(key string) interface{} {
	response := make(chan interface{})
	c.req <- &request{key: key, response: response, op: del}
	return <-response
}

// Clear removes all entries from the cache and returns the previous one
func (c *Cache) Clear() map[string]interface{} {
	response := make(chan interface{})
	c.req <- &request{response: response, op: clear}
	return (<-response).(map[string]interface{})
}

// Reset replaces the internal cache with the content argument and returns the previous one
func (c *Cache) Reset(content map[string]interface{}) map[string]interface{} {
	response := make(chan interface{})
	c.req <- &request{value: content, response: response, op: reset}
	return (<-response).(map[string]interface{})
}

// Snapshot returns a shallow copy of the cache
func (c *Cache) Snapshot() map[string]interface{} {
	resp := make(chan interface{})
	c.req <- &request{response: resp, op: snapshot}
	r := <-resp
	return r.(map[string]interface{})
}

// Close shuts down the cache in a clean way
func (c *Cache) Close() {
	close(c.quit)
}
