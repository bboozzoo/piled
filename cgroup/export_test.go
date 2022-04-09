package cgroup

func MockSysFsCgroup(p string) (restore func()) {
	old := sysFsCgroup
	sysFsCgroup = p
	return func() {
		sysFsCgroup = old
	}
}

func MockProcSelfCgroup(p string) (restore func()) {
	old := procSelfCgroup
	procSelfCgroup = p
	return func() {
		procSelfCgroup = old
	}
}
