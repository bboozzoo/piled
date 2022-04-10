package testutils

import (
	. "gopkg.in/check.v1"
)

type BaseTest struct {
	cleanups []func()
}

func (b *BaseTest) AddCleanup(restore func()) {
	b.cleanups = append(b.cleanups, restore)
}

func (b *BaseTest) SetUpTest(c *C) {}

func (b *BaseTest) TearDownTest(c *C) {
	for _, restore := range b.cleanups {
		restore()
	}
}
