package geodata

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/sagernet/sing/common/control"
)

// Fetch is for the initial direct download, before the routing core is up.
// Through-outbound downloads use the running core's authenticated controller.
func Fetch(ctx context.Context, address string, routingMark uint32, output io.Writer) error {
	u, err := url.Parse(address)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("expected HTTP(S) URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if routingMark != 0 {
		dialer := &net.Dialer{Control: control.RoutingMark(routingMark)}
		// Bootstrap DNS must bypass the router's transparent DNS capture too.
		dialer.Resolver = &net.Resolver{PreferGo: true, Dial: dialer.DialContext}
		transport.DialContext = dialer.DialContext
	}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	const limit = 128 << 20
	if response.StatusCode != http.StatusOK || response.ContentLength > limit {
		return fmt.Errorf("geodata download refused: HTTP %d, length %d", response.StatusCode, response.ContentLength)
	}
	n, err := io.CopyBuffer(output, io.LimitReader(response.Body, limit+1), make([]byte, 32*1024))
	if err != nil {
		return err
	}
	if n == 0 || n > limit {
		return fmt.Errorf("geodata download is empty or exceeds 128 MiB")
	}
	return nil
}
