package cgroup_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bboozzoo/piled/cgroup"
)

func TestBasicGroupManipulation(t *testing.T) {
	root := t.TempDir()
	psc := filepath.Join(root, "proc-self-cgroup")
	t.Cleanup(cgroup.MockProcSelfCgroup(psc))
	t.Cleanup(cgroup.MockSysFsCgroup(root))

	err := os.WriteFile(psc, []byte("0::/a/b/c"), 0644)
	require.NoError(t, err)

	current, err := cgroup.Current()
	require.NoError(t, err)
	assert.Equal(t, "/a/b/c", current)

	cgRunner := filepath.Join(current, "runner")
	// precondition
	require.NoDirExists(t, filepath.Join(root, cgRunner))
	// add
	err = cgroup.Add(cgRunner)
	require.NoError(t, err)
	assert.DirExists(t, filepath.Join(root, cgRunner))
	// remove
	err = cgroup.Remove(cgRunner)
	require.NoError(t, err)
	assert.NoDirExists(t, filepath.Join(root, cgRunner))
	// but only the leaf is removed
	assert.DirExists(t, filepath.Join(root, filepath.Dir(cgRunner)))
}

func TestProperties(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(cgroup.MockSysFsCgroup(root))

	err := cgroup.Add("/a/b/c/d")
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(root, "a/b/c/d/memory.max"), nil, 0644)
	require.NoError(t, err)

	for _, tc := range []struct {
		got, want string
	}{
		{got: "1", want: "1\n"},
		{got: "2", want: "2\n"},
	} {
		err = cgroup.WriteProperty("/a/b/c/d", "memory.max", tc.got)
		require.NoError(t, err)
		d, err := os.ReadFile(filepath.Join(root, "/a/b/c/d/memory.max"))
		require.NoError(t, err)
		assert.Equal(t, tc.want, string(d))
	}

	val := `
low 0
high 0
max 954
oom 0
oom_kill 0
oom_group_kill 1
`
	err = os.WriteFile(filepath.Join(root, "a/b/c/d/memory.events.local"), []byte(val), 0644)
	require.NoError(t, err)
	v, err := cgroup.ReadKVProperty("/a/b/c/d", "memory.events.local", "max")
	require.NoError(t, err)
	assert.Equal(t, "954", v)
	v, err = cgroup.ReadKVProperty("/a/b/c/d", "memory.events.local", "oom_group_kill")
	require.NoError(t, err)
	assert.Equal(t, "1", v)
	_, err = cgroup.ReadKVProperty("/a/b/c/d", "memory.events.local", "missing")
	assert.Equal(t, cgroup.KeyNotFoundError, err)
	err = os.WriteFile(filepath.Join(root, "a/b/c/d/memory.events.local"), []byte(`invalid`), 0644)
	require.NoError(t, err)
	_, err = cgroup.ReadKVProperty("/a/b/c/d", "memory.events.local", "missing")
	require.EqualError(t, err, `cannot process line "invalid"`)
}

func TestMoveTo(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(cgroup.MockSysFsCgroup(root))

	err := cgroup.Add("/a/b/c/d")
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(root, "a/b/c/d/cgroup.procs"), nil, 0644)
	require.NoError(t, err)
	err = cgroup.MovePidTo(1, "/a/b/c/d")
	require.NoError(t, err)
	d, err := os.ReadFile(filepath.Join(root, "/a/b/c/d/cgroup.procs"))
	require.NoError(t, err)
	assert.Equal(t, "1\n", string(d))
}

func TestOccupied(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(cgroup.MockSysFsCgroup(root))

	err := cgroup.Add("/a/b/c/d")
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(root, "a/b/c/d/cgroup.procs"), nil, 0644)
	require.NoError(t, err)
	occupied, err := cgroup.Occupied("/a/b/c/d")
	require.NoError(t, err)
	assert.False(t, occupied)

	err = os.WriteFile(filepath.Join(root, "a/b/c/d/cgroup.procs"), []byte("1234"), 0644)
	require.NoError(t, err)
	occupied, err = cgroup.Occupied("/a/b/c/d")
	require.NoError(t, err)
	assert.True(t, occupied)

	occupied, err = cgroup.Occupied("/a/not-found")
	require.Error(t, err)
	assert.Regexp(t, "cannot open cgroup processes: open.*/a/not-found/cgroup.procs: no such file or directory",
		err.Error())
	assert.False(t, occupied)
}
