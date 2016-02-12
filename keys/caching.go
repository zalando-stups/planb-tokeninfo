package keys

type Cache struct {
	req  chan *request
	quit chan struct{}
}

type operation int

const (
	get operation = iota
	set
	snapshot
)

type request struct {
	op       operation
	key      string
	value    interface{}
	response chan interface{}
}

func NewCache() *Cache {
	req := make(chan *request)
	quit := make(chan struct{})

	go func() {
		m := make(map[string]interface{})

		for {
			select {
			case r := <-req:
				r.response <- doOp(m, r)
			case <-quit:
				return
			}

		}
	}()

	return &Cache{req, quit}
}

func doOp(m map[string]interface{}, r *request) interface{} {
	switch r.op {
	case set:
		m[r.key] = r.value
		return r.value
	case get:
		return m[r.key]
	case snapshot:
		newMap := make(map[string]interface{})
		for k, v := range m {
			newMap[k] = v
		}
		return newMap
	default:
		panic("Unsupported cache operation")
	}
}

func (c *Cache) Get(key string) interface{} {
	response := make(chan interface{})
	c.req <- &request{key: key, response: response, op: get}
	return <-response
}

func (c *Cache) Set(key string, value interface{}) interface{} {
	response := make(chan interface{})
	c.req <- &request{key: key, value: value, response: response, op: set}
	return <-response
}

func (c *Cache) Snapshot() map[string]interface{} {
	resp := make(chan interface{})
	c.req <- &request{response: resp, op: snapshot}
	r := <-resp
	return r.(map[string]interface{})
}

func (c *Cache) Close() {
	close(c.quit)
}
