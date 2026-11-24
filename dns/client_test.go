package dns

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestCachedExchangeUsesRequestIDAndChecksResponse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := NewClient(ClientOptions{Context: ctx})
	transport := &fakeDNSTransport{tag: "test", immediate: true}
	options := adapter.DNSQueryOptions{}
	request := new(mDNS.Msg).SetQuestion("example.test.", mDNS.TypeA)
	key := client.newCacheKey(transport, request.Question[0], request, options)
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	client.storeCache(key, FixedResponse(1, request.Question[0], addresses, 3600), 3600)

	request.Id = 2
	response, err := client.Exchange(ctx, transport, request, options, nil)
	require.NoError(t, err)
	require.Equal(t, request.Id, response.Id)
	response.Answer[0].Header().Ttl = 0

	request.Id = 3
	called := false
	client.ExchangeAsync(ctx, transport, request, options, nil, func(response *mDNS.Msg, err error) {
		called = true
		require.NoError(t, err)
		require.Equal(t, request.Id, response.Id)
		require.Positive(t, response.Answer[0].Header().Ttl)
	})
	require.True(t, called, "a cached response should be delivered immediately")

	response, err = client.Exchange(ctx, transport, request, options, func(*mDNS.Msg) bool { return false })
	require.ErrorIs(t, err, ErrResponseRejectedCached)
	require.Nil(t, response)
	require.Zero(t, transport.queryCount.Load())
}

func TestExpiredCacheLookupKeepsConcurrentRefresh(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		const optimisticTimeout = time.Minute
		client := NewClient(ClientOptions{Context: ctx, OptimisticTimeout: optimisticTimeout})
		transport := &fakeDNSTransport{tag: "test", address: netip.MustParseAddr("192.0.2.1")}
		request := new(mDNS.Msg).SetQuestion("example.test.", mDNS.TypeA)
		key := client.newCacheKey(transport, request.Question[0], request, adapter.DNSQueryOptions{})

		var hashCalls atomic.Int32
		lookupPaused := make(chan struct{})
		resumeLookup := make(chan struct{})
		client.cache = client.newMemoryCache(func(dnsCacheKey) uint32 {
			// Pause after the initial lookup has observed the expired entry.
			if hashCalls.Add(1) == 3 {
				close(lookupPaused)
				<-resumeLookup
			}
			return 0
		})
		client.storeCache(key, FixedResponse(1, request.Question[0], []netip.Addr{transport.address}, 1), 1)
		time.Sleep(optimisticTimeout + 2*time.Second)

		firstRequest := request.Copy()
		firstErr := make(chan error, 1)
		go func() {
			_, err := client.Exchange(ctx, transport, firstRequest, adapter.DNSQueryOptions{Timeout: time.Second}, nil)
			firstErr <- err
		}()
		<-lookupPaused
		// A different timeout uses a separate exchange slot for the same cached name.
		_, err := client.Exchange(ctx, transport, request, adapter.DNSQueryOptions{Timeout: 2 * time.Second}, nil)
		close(resumeLookup)
		require.NoError(t, err)
		require.NoError(t, <-firstErr)
		require.Equal(t, int32(1), transport.queryCount.Load())
	})
}

func TestLoadResponseSkipsStaleMaterialization(t *testing.T) {
	question := mDNS.Question{Name: "example.test.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}
	key := dnsCacheKey{Question: question}
	message := FixedResponse(1, question, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)
	packed, err := message.Pack()
	require.NoError(t, err)

	for _, storage := range []string{"memory", "persistent"} {
		t.Run(storage, func(t *testing.T) {
			client := NewClient(ClientOptions{Context: t.Context(), OptimisticTimeout: time.Hour})
			if storage == "memory" {
				client.cache.Add(key, dnsCacheEntry{response: message, expiresAtMillis: time.Now().Add(-time.Minute).UnixMilli()})
			} else {
				client.dnsCache = &staleDNSCache{message: packed, expireAt: time.Now().Add(-time.Minute)}
			}

			var response *mDNS.Msg
			allocations := testing.AllocsPerRun(5, func() { response, _, _ = client.loadResponse(key, false) })
			require.Nil(t, response)
			require.Zero(t, allocations)

			response, _, stale := client.loadResponse(key, true)
			require.True(t, stale)
			require.NotNil(t, response)
			require.Equal(t, uint32(1), response.Answer[0].Header().Ttl)
		})
	}
}

type staleDNSCache struct {
	adapter.DNSCacheStore
	message  []byte
	expireAt time.Time
}

func (c *staleDNSCache) LoadDNSCache(string, string, uint16) ([]byte, time.Time, bool) {
	return c.message, c.expireAt, true
}
