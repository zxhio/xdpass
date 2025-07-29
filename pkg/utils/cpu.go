package utils

import "golang.org/x/sys/unix"

func SetAffinityCPU(cpu int) error {
	var s unix.CPUSet
	s.Zero()
	s.Set(cpu)
	return unix.SchedSetaffinity(0, &s)
}
