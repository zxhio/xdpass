package netutil

import (
	"os"
	"path"
)

const sysNetPath = "/sys/class/net"

func IsPhyNic(nic string) bool {
	_, err := os.Stat(path.Join(sysNetPath, nic, "device"))
	return err == nil
}
