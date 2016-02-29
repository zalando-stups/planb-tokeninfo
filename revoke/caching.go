package revoke

import (
	"github.com/zalando/planb-tokeninfo/options"
	"time"
)

// TODO: consider adding a separate cache for each revocation type

type Cache struct {
	get    chan *request
	set    chan *request
	del    chan *request
	expire chan bool
	ts     chan *request
	cName  chan *request
}

type request struct {
	key string
	val interface{}
	res chan interface{}
}

func NewCache() *Cache {

	get := make(chan *request)
	set := make(chan *request)
	del := make(chan *request)
	expire := make(chan bool)
	ts := make(chan *request)
	cName := make(chan *request)

	go func() {
		c := make(map[string]interface{})

		for {
			select {
			case r := <-set:
				c[r.key] = r.val
			case r := <-del:
				delete(c, r.key)
			case <-expire:
				for key, revocation := range c {
					if isExpired(revocation.(*Revocation).Timestamp) {
						delete(c, key)
					}
				}
			case r := <-ts:
				t := 0
				key := ""
				for k, rev := range c {
					if rev.(*Revocation).Timestamp > t {
						t = rev.(*Revocation).Timestamp
						key = k
					}
				}
				r.res <- c[key]
			case r := <-cName:
				names := make(map[string]int)
				for _, rev := range c {
					if rev.(*Revocation).Type == "CLAIM" {
						names[rev.(*Revocation).Data["name"].(string)] = 1
					}
				}
				r.res <- names
			case r := <-get:
				r.res <- c[r.key]
			}
		}
	}()

	return &Cache{get: get, set: set, del: del, expire: expire, ts: ts, cName: cName}
}

func (c *Cache) Get(key string) interface{} {
	res := make(chan interface{})
	c.get <- &request{key: key, res: res}
	return <-res
}

func (c *Cache) GetLastTS() int {
	res := make(chan interface{})
	c.ts <- &request{res: res}
	r := <-res
	if r == nil {
		return 0
	}
	return r.(*Revocation).Timestamp
}

func (c *Cache) GetClaimNames() []string {
	res := make(chan interface{})
	c.cName <- &request{res: res}
	r := <-res
	var names []string
	for n, _ := range r.(map[string]int) {
		names = append(names, n)
	}

	return names
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
		hash = rev.Data["name"].(string) + rev.Data["value_hash"].(string)
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

	if ts-int(options.AppSettings.RevokeExpireLength) < int(time.Now().UnixNano()/1e6) {
		return true
	}

	return false
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
