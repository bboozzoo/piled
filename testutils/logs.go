package testutils

import (
	"bytes"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

func MockLogger(t *testing.T) *bytes.Buffer {
	buf := &bytes.Buffer{}
	logrus.SetOutput(buf)

	t.Cleanup(func() {
		logrus.SetOutput(os.Stderr)
	})
	return buf
}
