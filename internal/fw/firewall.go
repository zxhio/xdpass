package fw

import (
	"errors"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/zxhio/xdpass/pkg/inet"
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type Firewall struct {
	ifaceName string
	trie      *ebpf.Map
	keys      map[inet.LPMIPv4]struct{}
	mu        *sync.Mutex
}

func NewFirewall(ifaceName string, trie *ebpf.Map) *Firewall {
	return &Firewall{
		ifaceName: ifaceName,
		trie:      trie,
		keys:      make(map[inet.LPMIPv4]struct{}),
		mu:        &sync.Mutex{},
	}
}

func (f *Firewall) AddIPKey(key inet.LPMIPv4) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// TODO: Aggregate these keys

	err := f.trie.Update(xdpprog.NewIPLpmKey(key), uint8(0), 0)
	if err != nil {
		return err
	}
	f.keys[key] = struct{}{}
	return nil
}

func (f *Firewall) DelIPKey(key inet.LPMIPv4) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	err := f.trie.Delete(xdpprog.NewIPLpmKey(key))
	if err != nil {
		return err
	}
	delete(f.keys, key)
	return nil
}

func (f *Firewall) ListIPKey() ([]inet.LPMIPv4, error) {
	var (
		key     xdpprog.IPLpmKey
		nextKey xdpprog.IPLpmKey
		lpms    []inet.LPMIPv4
	)

	for {
		err := f.trie.NextKey(&key, &nextKey)
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, err
		}
		key = nextKey
		lpms = append(lpms, key.ToLPMIPv4())
	}
	return lpms, nil
}
