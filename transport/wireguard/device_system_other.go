//go:build !linux || android

package wireguard

import "github.com/sagernet/sing-tun"

func startSystemTun(options tun.Options) (tun.Tun, func() error, error) {
	device, err := openSystemTun(options)
	return device, nil, err
}
