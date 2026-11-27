//go:build !linux

package desync

import "fmt"

func verifyScale(_ any, want int, explicit bool) error {
	if want != 0 || explicit {
		return fmt.Errorf("desync: wscale requires Linux")
	}
	return nil
}
