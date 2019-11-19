package jwt

import (
	"fmt"
	"sync"
)

type id string

func (s id) ptr() *id { return &s }

type mDB struct {
	m  map[string]*id
	mu sync.RWMutex
}

var tokenDB mDB = mDB{
	m: make(map[string]*id),
}

func (db mDB) Get(name string) (*id, error) {
	db.mu.RLock()
	u, ok := db.m[name]
	db.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%s does not exist", name)
	}
	return u, nil
}

func (db mDB) Put(k, v *id) error {
	db.mu.Lock()
	db.m[string(*k)] = v
	db.mu.Unlock()
	return nil
}

func (db mDB) Delete(k *id) error {
	db.mu.Lock()
	delete(db.m, string(*k))
	db.mu.Unlock()
	return nil
}

func (db mDB) Listed(k string) bool {
	db.mu.RLock()
	_, ok := db.m[k]
	db.mu.RUnlock()
	return ok
}
