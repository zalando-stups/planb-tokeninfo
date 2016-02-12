package keys

type Cache struct {
	get chan *request
	set chan *request
}

type request struct {
	key      string
	value    interface{}
	response chan interface{}
}

func NewCache() *Cache {
	get := make(chan *request)
	set := make(chan *request)

	go func() {
		m := make(map[string]interface{})

		for {
			select {
			case r := <-get:
				r.response <- m[r.key]
			case r := <-set:
				m[r.key] = r.value
				r.response <- r.value
			}
		}
	}()

	return &Cache{get, set}
}

func (c *Cache) Get(key string) interface{} {
	response := make(chan interface{})
	c.get <- &request{key: key, response: response}
	return <-response
}

func (c *Cache) Set(key string, value interface{}) interface{} {
	response := make(chan interface{})
	c.set <- &request{key: key, value: value, response: response}
	return <-response
}
