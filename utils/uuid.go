package utils

import (
	"bytes"
	"io/ioutil"
)

func UUID() (string, error) {
	d, err := ioutil.ReadFile("/proc/sys/kernel/random/uuid")
	if err != nil {
		return "", err
	}
	d = bytes.TrimSpace(d)
	return string(d), nil
}
