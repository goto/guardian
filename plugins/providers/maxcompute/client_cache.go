package maxcompute

import (
	"sync"

	"github.com/goto/guardian/pkg/aliclientmanager"
)

// Credential initialization may use the network, so it runs outside the lock.
// Concurrent misses keep the first initialized manager rather than replacing it.
func cachedClientManager[T any](mu *sync.Mutex, cache map[string]*aliclientmanager.Manager[T], key string, create func() (*aliclientmanager.Manager[T], error)) (*aliclientmanager.Manager[T], error) {
	mu.Lock()
	manager, found := cache[key]
	mu.Unlock()
	if found {
		return manager, nil
	}
	candidate, err := create()
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	if manager, found = cache[key]; found {
		return manager, nil
	}
	cache[key] = candidate
	return candidate, nil
}
