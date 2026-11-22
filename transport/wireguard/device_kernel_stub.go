//go:build !linux || android

package wireguard

func startKernelDevice(*Endpoint) (kernelDevice, error) {
	return nil, errKernelUnavailable
}
