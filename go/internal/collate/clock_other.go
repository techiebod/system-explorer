//go:build !linux

package collate

// No time namespaces outside Linux, so the collator's own offset is zero
// and a collector reporting non-zero is still a mismatch worth stating —
// the comparison is meaningful on a development machine even though the
// collator's side can only ever be zero there.
func timensOffset() int64 { return 0 }
