package cgroup_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/bboozzoo/piled/cgroup"
	"github.com/bboozzoo/piled/testutils"
)

func Test(t *testing.T) {
	TestingT(t)
}

var _ = Suite(&cgroupSuite{})

type cgroupSuite struct {
	testutils.BaseTest
	root string
}

func (s *cgroupSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.root = c.MkDir()
	restore := cgroup.MockSysFsCgroup(s.root)
	s.AddCleanup(restore)
}

func (s *cgroupSuite) TestBasics(c *C) {
	psc := filepath.Join(s.root, "proc-self-cgroup")
	err := ioutil.WriteFile(psc, []byte("0::/a/b/c"), 0644)
	c.Assert(err, IsNil)
	cgroup.MockProcSelfCgroup(psc)

	current, err := cgroup.Current()
	c.Assert(err, IsNil)
	c.Assert(current, Equals, "/a/b/c")

	cgRunner := filepath.Join(current, "runner")
	// precondition
	_, err = os.Stat(filepath.Join(s.root, cgRunner))
	c.Assert(err, ErrorMatches, ".*/a/b/c/runner: no such file or directory")
	// add
	err = cgroup.Add(cgRunner)
	c.Assert(err, IsNil)
	st, err := os.Stat(filepath.Join(s.root, cgRunner))
	c.Assert(err, IsNil)
	c.Assert(st.Mode().IsDir(), Equals, true)
	// remove
	err = cgroup.Remove(cgRunner)
	c.Assert(err, IsNil)
	// the directory is gone
	_, err = os.Stat(filepath.Join(s.root, cgRunner))
	c.Assert(err, ErrorMatches, ".*/a/b/c/runner: no such file or directory")
	// but only the leaf is removed
	_, err = os.Stat(filepath.Join(s.root, filepath.Dir(cgRunner)))
	c.Assert(err, IsNil)
}

func (s *cgroupSuite) TestProperties(c *C) {
	err := cgroup.Add("/a/b/c/d")
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(filepath.Join(s.root, "a/b/c/d/memory.max"), nil, 0644)
	c.Assert(err, IsNil)

	for _, tc := range []struct {
		val, expected string
	}{
		{"1", "1\n"},
		{"2", "2\n"},
	} {
		err = cgroup.WriteProperty("/a/b/c/d", "memory.max", tc.val)
		c.Assert(err, IsNil)
		d, err := ioutil.ReadFile(filepath.Join(s.root, "/a/b/c/d/memory.max"))
		c.Assert(err, IsNil)
		c.Assert(string(d), DeepEquals, tc.expected)
	}

	val := `
low 0
high 0
max 954
oom 0
oom_kill 0
oom_group_kill 1
`
	err = ioutil.WriteFile(filepath.Join(s.root, "a/b/c/d/memory.events.local"), []byte(val), 0644)
	c.Assert(err, IsNil)
	v, err := cgroup.ReadKVProperty("/a/b/c/d", "memory.events.local", "max")
	c.Assert(err, IsNil)
	c.Assert(v, Equals, "954")
	v, err = cgroup.ReadKVProperty("/a/b/c/d", "memory.events.local", "oom_group_kill")
	c.Assert(err, IsNil)
	c.Assert(v, Equals, "1")
	_, err = cgroup.ReadKVProperty("/a/b/c/d", "memory.events.local", "missing")
	c.Assert(err, Equals, cgroup.KeyNotFoundError)
	err = ioutil.WriteFile(filepath.Join(s.root, "a/b/c/d/memory.events.local"), []byte(`invalid`), 0644)
	c.Assert(err, IsNil)
	_, err = cgroup.ReadKVProperty("/a/b/c/d", "memory.events.local", "missing")
	c.Assert(err, ErrorMatches, `cannot process line "invalid"`)
}

func (s *cgroupSuite) TestMoveTo(c *C) {
	err := cgroup.Add("/a/b/c/d")
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(filepath.Join(s.root, "a/b/c/d/cgroup.procs"), nil, 0644)
	c.Assert(err, IsNil)
	err = cgroup.MovePidTo(1, "/a/b/c/d")
	c.Assert(err, IsNil)
	d, err := ioutil.ReadFile(filepath.Join(s.root, "/a/b/c/d/cgroup.procs"))
	c.Assert(err, IsNil)
	c.Assert(string(d), DeepEquals, "1\n")
}

func (s *cgroupSuite) TestFreeze(c *C) {
	err := cgroup.Add("/a/b/c/d")
	c.Assert(err, IsNil)
	err = ioutil.WriteFile(filepath.Join(s.root, "a/b/c/d/cgroup.freeze"), nil, 0644)
	c.Assert(err, IsNil)

	err = cgroup.Freeze("/a/b/c/d")
	c.Assert(err, IsNil)
	d, err := ioutil.ReadFile(filepath.Join(s.root, "/a/b/c/d/cgroup.freeze"))
	c.Assert(err, IsNil)
	c.Assert(string(d), DeepEquals, "1\n")

	err = cgroup.Freeze("/a/not-found")
	c.Assert(err, ErrorMatches, "cannot open .*/a/not-found/cgroup.freeze: no such file or directory")

	err = cgroup.Unfreeze("/a/b/c/d")
	c.Assert(err, IsNil)
	d, err = ioutil.ReadFile(filepath.Join(s.root, "/a/b/c/d/cgroup.freeze"))
	c.Assert(err, IsNil)
	c.Assert(string(d), DeepEquals, "0\n")

	err = cgroup.Unfreeze("/a/not-found")
	c.Assert(err, ErrorMatches, "cannot open .*/a/not-found/cgroup.freeze: no such file or directory")
}

func (s *cgroupSuite) TestOccupied(c *C) {
	err := cgroup.Add("/a/b/c/d")
	c.Assert(err, IsNil)

	err = ioutil.WriteFile(filepath.Join(s.root, "a/b/c/d/cgroup.procs"), nil, 0644)
	c.Assert(err, IsNil)
	occupied, err := cgroup.Occupied("/a/b/c/d")
	c.Assert(err, IsNil)
	c.Assert(occupied, Equals, false)

	err = ioutil.WriteFile(filepath.Join(s.root, "a/b/c/d/cgroup.procs"), []byte("1234"), 0644)
	c.Assert(err, IsNil)
	occupied, err = cgroup.Occupied("/a/b/c/d")
	c.Assert(err, IsNil)
	c.Assert(occupied, Equals, true)

	occupied, err = cgroup.Occupied("/a/not-found")
	c.Assert(err, ErrorMatches, "cannot open cgroup processes: open .*/a/not-found/cgroup.procs: no such file or directory")
	c.Assert(occupied, Equals, false)
}
