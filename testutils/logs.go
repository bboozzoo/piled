package testutils

import (
	"bytes"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

func MockLogger(t *testing.T) *bytes.Buffer {
	oldOut := os.Stderr
	buf := &bytes.Buffer{}
	logrus.SetOutput(buf)

	t.Cleanup(func() {
		logrus.SetOutput(oldOut)
	})
	return buf
}
