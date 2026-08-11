package loader

import (
	"log"

	"github.com/shinagawa-web/tinytap/internal/drops"
)

const (
	dropSlotRingbuf = 0
	dropSlotMapFull = 1
)

type dropLookuper interface {
	Lookup(key, valueOut any) error
}

func readDrops(m dropLookuper) drops.Counts {
	return drops.Counts{
		Ringbuf: sumDropSlot(m, dropSlotRingbuf),
		MapFull: sumDropSlot(m, dropSlotMapFull),
	}
}

func sumDropSlot(m dropLookuper, slot uint32) uint64 {
	var vals []uint64
	if err := m.Lookup(&slot, &vals); err != nil {
		log.Printf("tinytap: read drop_counters slot %d: %v", slot, err)
		return 0
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total
}
