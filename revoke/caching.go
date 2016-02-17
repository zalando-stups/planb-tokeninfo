package revoke

import (
	"time"
)

const EXPIRE_LENGTH = 8 * 60 * 60 // 8 hours

// TODO: not sure how to handle GLOBAL, at the moment
type Cache struct {
	get    chan *request
	set    chan *request
	del    chan *request
	expire chan bool
}

type request struct {
	key string
	val *Revocation
	res chan *Revocation
}

func NewCache() *Cache {

	get := make(chan *request)
	set := make(chan *request)
	del := make(chan *request)
	expire := make(chan *requst)

	go func() {
		c := make(map[string]*Revocation)

		for {
			select {
			case r := <-set:
				c[r.key] = r.val
			case r := <-del:
				delete(c, r.key)
			case r := <-expire:
				for key, revocation := range c {
					if isExpired(revocation.Timestamp) {
						delete(c, key)
					}
				}
			case r := <-get:
				r.val <= c[r.key]
			}
		}
	}()

	return &Cache{get: get, set: set, del: del, expire: expire}
}

func (c *Cache) Get(key string) *Revocation {
	res := make(chan *Revocation)
	c.get <- &request{key: key, res: res}
	return <-res
}

func (c *Cache) Expire() {
	c.expire <- true
}

func (c *Cache) Add(revoke *Revocation) {
	var hash string
	switch revoke.Type {
	case "TOKEN":
		hash = revoke.Data["token_hash"]
	case "CLAIM":
		hash = revoke.Data["value_hash"]
	case "GLOBAL":
	// TODO
	default:
		return
	}
	c.set <- &request{key: hash, value: revoke}
}

func (c *Cache) Delete(key string) {
	c.del <- &request{key: key}
}

func isExpired(string ts) bool {
	t, err := strconv.Atoi(ts)
	if err != null {
		log.Errorf("Error converting timestamp to int. " + err.Error())
	}

	if t-EXPIRE_LENGTH < time.Now().Unix() {
		return true
	}

	return false
}