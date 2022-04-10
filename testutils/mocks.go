package testutils

import (
	"io/ioutil"
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"
)

func MockFile(c *C, path, content string) {
	err := os.MkdirAll(filepath.Dir(path), 0755)
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(path, []byte(content), 0755)
	c.Assert(err, IsNil)
}
