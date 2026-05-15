package xsk

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestProdQueueReserveAndSubmit(t *testing.T) {
	t.Parallel()

	// Simulate a ring of size 8 with all slots free.
	var prod, cons, flags uint32
	ring := make([]uint64, 8)
	q := &prodQueue[uint64]{
		cachedProd: 0,
		cachedCons: 8, // all free
		mask:       7,
		size:       8,
		producer:   &prod,
		consumer:   &cons,
		flags:      &flags,
		ring:       ring,
	}

	var idx uint32
	reserved := q.Reserve(3, &idx)
	if reserved != 3 {
		t.Fatalf("Reserve(3) = %d, want 3", reserved)
	}
	if idx != 0 {
		t.Fatalf("idx = %d, want 0", idx)
	}

	q.Submit(3)
	if prod != 3 {
		t.Fatalf("producer = %d, want 3", prod)
	}
}

func TestConsQueuePeekAndRelease(t *testing.T) {
	t.Parallel()

	var prod, cons, flags uint32
	prod = 5
	ring := make([]unix.XDPDesc, 8)
	q := &consQueue[unix.XDPDesc]{
		cachedProd: 5,
		cachedCons: 0,
		mask:       7,
		size:       8,
		producer:   &prod,
		consumer:   &cons,
		flags:      &flags,
		ring:       ring,
	}

	var idx uint32
	avail := q.Peek(3, &idx)
	if avail != 3 {
		t.Fatalf("Peek(3) = %d, want 3", avail)
	}
	if idx != 0 {
		t.Fatalf("idx = %d, want 0", idx)
	}

	q.Release(3)
	if cons != 3 {
		t.Fatalf("consumer = %d, want 3", cons)
	}
}
