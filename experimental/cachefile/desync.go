package cachefile

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/sagernet/bbolt"
)

var bucketDesync = []byte("desync_v1")

type desyncPending struct {
	sync.Mutex
	pending map[string][]byte
	timer   *time.Timer
	closed  bool
}

func (c *CacheFile) LoadDesync(partition string) ([]byte, error) {
	c.desync.Lock()
	if data, ok := c.desync.pending[partition]; ok {
		result := append([]byte(nil), data...)
		c.desync.Unlock()
		return result, nil
	}
	c.desync.Unlock()
	var result []byte
	err := c.view(func(tx *bbolt.Tx) error {
		bucket := c.bucket(tx, bucketDesync)
		if bucket != nil {
			result = append([]byte(nil), bucket.Get([]byte(partition))...)
		}
		return nil
	})
	return result, err
}

// StoreDesync coalesces snapshots per partition. No network event writes to disk.
func (c *CacheFile) StoreDesync(partition string, data []byte) error {
	if len(partition) > 256 || len(data) > 16<<20 || !json.Valid(data) {
		return fmt.Errorf("invalid desync snapshot")
	}
	c.desync.Lock()
	defer c.desync.Unlock()
	if c.desync.closed {
		return fmt.Errorf("desync cache closed")
	}
	if c.desync.pending == nil {
		c.desync.pending = map[string][]byte{}
	}
	if _, ok := c.desync.pending[partition]; !ok && len(c.desync.pending) >= 128 {
		return fmt.Errorf("too many pending desync partitions")
	}
	total := len(data)
	for key, value := range c.desync.pending {
		if key != partition {
			total += len(value)
		}
	}
	if total > 32<<20 {
		return fmt.Errorf("pending desync snapshots exceed 32 MiB")
	}
	c.desync.pending[partition] = append([]byte(nil), data...)
	if c.desync.timer == nil {
		c.desync.timer = time.AfterFunc(5*time.Second, func() {
			if err := c.FlushDesync(); err != nil {
				c.logger.Error("flush desync cache: ", err)
			}
		})
	}
	return nil
}
func (c *CacheFile) FlushDesync() error {
	c.desync.Lock()
	defer c.desync.Unlock()
	if c.desync.timer != nil {
		c.desync.timer.Stop()
		c.desync.timer = nil
	}
	if len(c.desync.pending) == 0 {
		return nil
	}
	err := c.batch(func(tx *bbolt.Tx) error {
		bucket, err := c.createBucket(tx, bucketDesync)
		if err != nil {
			return err
		}
		for key, data := range c.desync.pending {
			if err = bucket.Put([]byte(key), data); err != nil {
				return err
			}
		}
		var stale [][]byte
		var count, total int
		now := time.Now()
		if err = bucket.ForEach(func(key, data []byte) error {
			count++
			total += len(data)
			var snap struct {
				Entries map[string]struct {
					Updated time.Time `json:"updated"`
				} `json:"entries"`
			}
			if json.Unmarshal(data, &snap) == nil && len(snap.Entries) > 0 {
				latest := time.Time{}
				for _, entry := range snap.Entries {
					if entry.Updated.After(latest) {
						latest = entry.Updated
					}
				}
				if now.Sub(latest) > 7*24*time.Hour {
					stale = append(stale, append([]byte(nil), key...))
				}
			}
			return nil
		}); err != nil {
			return err
		}
		for _, key := range stale {
			if data := bucket.Get(key); data != nil {
				total -= len(data)
				count--
			}
			if err = bucket.Delete(key); err != nil {
				return err
			}
		}
		cursor := bucket.Cursor()
		for count > 128 || total > 64<<20 {
			key, data := cursor.First()
			if key == nil {
				break
			}
			total -= len(data)
			count--
			if err = cursor.Delete(); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		c.desync.pending = nil
	}
	return err
}
func (c *CacheFile) ClearDesync(partition string) error {
	c.desync.Lock()
	defer c.desync.Unlock()
	if partition == "" {
		c.desync.pending = nil
	} else {
		delete(c.desync.pending, partition)
	}
	return c.batch(func(tx *bbolt.Tx) error {
		bucket := c.bucket(tx, bucketDesync)
		if bucket == nil {
			return nil
		}
		if partition != "" {
			return bucket.Delete([]byte(partition))
		}
		var keys [][]byte
		if err := bucket.ForEach(func(k, v []byte) error { keys = append(keys, append([]byte(nil), k...)); return nil }); err != nil {
			return err
		}
		for _, key := range keys {
			if err := bucket.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}
func (c *CacheFile) closeDesync() error {
	c.desync.Lock()
	c.desync.closed = true
	c.desync.Unlock()
	return c.FlushDesync()
}
