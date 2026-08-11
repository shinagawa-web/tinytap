package loader

import (
	"errors"
	"testing"
)

type fakeLookuper struct {
	vals map[uint32][]uint64
	err  error
}

func (f *fakeLookuper) Lookup(key, valueOut any) error {
	if f.err != nil {
		return f.err
	}
	*(valueOut.(*[]uint64)) = f.vals[*(key.(*uint32))]
	return nil
}

func TestReadDrops_SumsPerCPUValues(t *testing.T) {
	f := &fakeLookuper{vals: map[uint32][]uint64{
		dropSlotRingbuf: {1, 2, 3},
		dropSlotMapFull: {10},
	}}
	got := readDrops(f)
	if got.Ringbuf != 6 {
		t.Errorf("Ringbuf = %d, want 6", got.Ringbuf)
	}
	if got.MapFull != 10 {
		t.Errorf("MapFull = %d, want 10", got.MapFull)
	}
}

func TestReadDrops_LookupError(t *testing.T) {
	f := &fakeLookuper{err: errors.New("boom")}
	got := readDrops(f)
	if got.Ringbuf != 0 || got.MapFull != 0 {
		t.Errorf("readDrops on lookup error = %+v, want zero", got)
	}
}

func TestSumDropSlot_EmptySlice(t *testing.T) {
	f := &fakeLookuper{vals: map[uint32][]uint64{}}
	if got := sumDropSlot(f, dropSlotRingbuf); got != 0 {
		t.Errorf("sumDropSlot on empty slice = %d, want 0", got)
	}
}
