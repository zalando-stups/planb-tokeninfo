package revoke

import (
	"github.com/zalando/planb-tokeninfo/options"
	"log"
	"time"
)

// TODO: consider adding a separate cache for each revocation type

// Cache structure holds all channels for available thread safe operations.
type Cache struct {
	get          chan *request
	set          chan *request
	del          chan *request
	expire       chan bool
	ts           chan *request // timestamp
	cName        chan *request // claim names
	forceRefresh chan int      // expire from timestamp
}

// request structure holds key-value/result pairs that are transferred through the cache channels.
type request struct {
	key string
	val interface{}
	res chan interface{}
}

// Return a new revocation Cache instance.
func NewCache() *Cache {

	get := make(chan *request)
	set := make(chan *request)
	del := make(chan *request)
	expire := make(chan bool)
	ts := make(chan *request)
	cName := make(chan *request)
	forceRefresh := make(chan int)

	go func() {
		c := make(map[string]interface{}) // store revocations
		n := make(map[string]int)         // store all claim names
		t := 0                            // store last pull timestamp

		for {
			select {
			case r := <-set:
				if r.val.(*Revocation).Type == REVOCATION_TYPE_CLAIM {
					n[r.val.(*Revocation).Data["names"].(string)] += 1
				}
				if r.val.(*Revocation).Type == REVOCATION_TYPE_FORCEREFRESH ||
					r.val.(*Revocation).Data["revoked_at"].(int) > t {
					t = r.val.(*Revocation).Data["revoked_at"].(int)
				}
				c[r.key] = r.val
			case r := <-del:
				delete(c, r.key)
			case r := <-forceRefresh:
				for key, rev := range c {
					if key != REVOCATION_TYPE_FORCEREFRESH && rev.(*Revocation).Data["revoked_at"].(int) >= r {
						if rev.(*Revocation).Type == REVOCATION_TYPE_CLAIM {
							n[rev.(*Revocation).Data["names"].(string)] -= 1
						}
						delete(c, key)
					}
				}
				for name, count := range n {
					if count == 0 {
						delete(n, name)
					}
				}
			case r := <-ts:
				if t != 0 {
					r.res <- t
				} else {
					r.res <- nil
				}
			case r := <-cName:
				r.res <- n
			case <-expire:
				for key, rev := range c {
					if isExpired(rev.(*Revocation).Data["revoked_at"].(int)) {
						if rev.(*Revocation).Type == REVOCATION_TYPE_CLAIM {
							n[rev.(*Revocation).Data["names"].(string)] -= 1
						}
						delete(c, key)
					}
				}
				for name, count := range n {
					if count == 0 {
						delete(n, name)
					}
				}
			case r := <-get:
				r.res <- c[r.key]
			}
		}
	}()

	return &Cache{get: get, set: set, del: del, expire: expire, ts: ts, cName: cName, forceRefresh: forceRefresh}
}

// Returns the value of a key in the revocation cache. nil if the key does not exist.
func (c *Cache) Get(key string) interface{} {
	res := make(chan interface{})
	c.get <- &request{key: key, res: res}
	return <-res
}

// Returns the latest revocation timestamp from the cache. i.e. get the last timestamp where a new revocation was found.
// Used for polling the next delta from the Revocation Service.
func (c *Cache) GetLastTS() int {
	res := make(chan interface{})
	c.ts <- &request{res: res}
	r := <-res
	if r == nil {
		return 0
	}
	return r.(int)
}

// Returns an array of all claim names stored in the cache.
// Used for revoking tokens based on the claim name/value.
// If a revocation has multiple claim names, there are stored separated by a '|' (e.g. 'name1|name2|. . .|nameN').
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

// Expire (delete) elements stored in the cache based on the REVOCATION_CACHE_TTL environment variable.
func (c *Cache) Expire() {
	c.expire <- true
}

// Delete all elements in the cache that were inserted after the given timestamp parameter.
// Used in case incorrect data was received from the Revocation Provider.
func (c *Cache) ForceRefresh(ts int) {
	if ts < int(time.Now().Add(-1*options.AppSettings.RevocationCacheTTL).Unix()) {
		return
	}
	c.forceRefresh <- ts
}

// Insert a revocation into the cache. Only allows specific revocation types (i.e. TOKEN, CLAIM, GLOBAL, FORCEREFRESH).
// REVOCATION_TYPE_TOKEN stores the key as a hash of the JWT.
// REVOCATION_TYPE_CLAIM stores the key as a hash of the name values (each value separated by a '|')
// REVOCATION_TYPE_GLOBAL stores the key as 'GLOBAL' as there can only be one golbal revocation.
// REVOCATION_TYPE_FORCEREFRESH stores the key as 'FORCEREFRESH as there can only be one force refresh.
func (c *Cache) Add(rev *Revocation) {
	var hash string
	switch rev.Type {
	case REVOCATION_TYPE_TOKEN:
		if _, ok := rev.Data["token_hash"]; !ok {
			log.Println("Error adding revocation to cache: missing token_hash.")
			return
		}
		hash = rev.Data["token_hash"].(string)
	case REVOCATION_TYPE_CLAIM:
		if _, ok := rev.Data["names"]; !ok {
			log.Println("Error adding revocation to cache: missing claim names.")
			return
		}
		if _, ok := rev.Data["value_hash"]; !ok {
			log.Println("Error adding revocation to cache: missing claim values hash.")
			return
		}
		hash = rev.Data["value_hash"].(string)
	case REVOCATION_TYPE_GLOBAL:
		hash = REVOCATION_TYPE_GLOBAL
	case REVOCATION_TYPE_FORCEREFRESH:
		hash = REVOCATION_TYPE_FORCEREFRESH
	default:
		log.Printf("Error adding revocation to cache. Unknown revocation type: %s", rev.Type)
		return
	}
	c.set <- &request{key: hash, val: rev}
}

// Remove an element from the cache based on its key.
func (c *Cache) Delete(key string) {
	c.del <- &request{key: key}
}

// Test if a cache element is expired. Uses the time a revocation was revoked and the environment variable
// REVOCATION_CACHE_TTL.
func isExpired(ts int) bool {

	if time.Unix(int64(ts), 0).Add(options.AppSettings.RevocationCacheTTL).Before(time.Now()) {
		return true
	}

	return false
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
