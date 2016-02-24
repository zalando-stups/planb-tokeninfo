package revoke

import (
	"github.com/zalando/planb-tokeninfo/options"
	"strconv"
	"time"
)

type Cache struct {
	get    chan *request
	set    chan *request
	del    chan *request
	expire chan bool
	ts     chan *request
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
	expire := make(chan bool)
	ts := make(chan *request)

	go func() {
		c := make(map[string]*Revocation)

		for {
			select {
			case r := <-set:
				c[r.key] = r.val
			case r := <-del:
				delete(c, r.key)
			case <-expire:
				for key, revocation := range c {
					if isExpired(revocation.Timestamp) {
						delete(c, key)
					}
				}
			case r := <-ts:
				t := 0
				key := ""
				for k, rev := range c {
					if rev.Timestamp > t {
						t = rev.Timestamp
						key = k
					}
				}
				r.res <- c[key]
			case r := <-get:
				r.res <- c[r.key]
			}
		}
	}()

	return &Cache{get: get, set: set, del: del, expire: expire, ts: ts}
}

func (c *Cache) Get(key string) *Revocation {
	res := make(chan *Revocation)
	c.get <- &request{key: key, res: res}
	return <-res
}

func (c *Cache) GetLastTS() string {
	res := make(chan *Revocation)
	c.ts <- &request{res: res}
	r := <-res
	if r.Timestamp == 0 {
		return ""
	}
	return strconv.Itoa(r.Timestamp)
}

func (c *Cache) Expire() {
	c.expire <- true
}

func (c *Cache) Add(rev *Revocation) {
	var hash string
	switch rev.Type {
	case "TOKEN":
		hash = rev.Data["token_hash"].(string)
	case "CLAIM":
		hash = rev.Data["value_hash"].(string)
	case "GLOBAL":
		hash = "GLOBAL"
	default:
		return
	}
	c.set <- &request{key: hash, val: rev}
}

func (c *Cache) Delete(key string) {
	c.del <- &request{key: key}
}

func isExpired(ts int) bool {

	if ts-int(options.RevokeExpireLength) < int(time.Now().UnixNano()/1e6) {
		return true
	}

	return false
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
