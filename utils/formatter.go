package utils

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

type WithPidFormatter struct {
	logrus.TextFormatter
}

func (w *WithPidFormatter) Format(en *logrus.Entry) ([]byte, error) {
	// TODO: actually figure out how to use fields
	l, err := w.TextFormatter.Format(en)
	if err != nil {
		return nil, err
	}
	pidPrefix := fmt.Sprintf("[%v]", os.Getpid())
	lWithPid := append([]byte(pidPrefix), l...)
	return lWithPid, nil
}
