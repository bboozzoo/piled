package main

import (
	"io"
)

var (
	Parser = parser
)

func MockStdout(w io.Writer) (restore func()) {
	old := stdout
	stdout = w
	return func() {
		stdout = old
	}
}
