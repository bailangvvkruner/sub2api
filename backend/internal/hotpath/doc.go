// Package hotpath owns process-local mutable state used by the request data
// plane. Implementations in this package serve L1 before delegating misses or
// configured write-through operations to service interfaces supplied by the
// application composition root.
//
// Administrative writes remain authoritative outside this package and must
// explicitly invalidate or refresh their corresponding L1 state.
package hotpath
