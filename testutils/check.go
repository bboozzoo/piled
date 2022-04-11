package testutils

import (
	"io/ioutil"

	. "gopkg.in/check.v1"
)

func TextFileEquals(c *C, p, val string) {
	// TODO convert to real checker
	d, err := ioutil.ReadFile(p)
	c.Assert(err, IsNil)
	c.Assert(string(d), DeepEquals, val)
}
