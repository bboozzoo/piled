package utils

import (
	"github.com/jessevdk/go-flags"
)

// IsErrHelp returns true when error indicates that help was shown
func IsErrHelp(err error) bool {
	ferr, ok := err.(*flags.Error)
	return ok && ferr.Type == flags.ErrHelp
}
