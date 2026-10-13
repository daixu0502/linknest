package access

import (
	"net/netip"
	"sort"
)

// Lookup time depends on distinct prefix lengths (at most 32/128), not feed size.
type prefixSet struct {
	items  map[netip.Prefix]struct{}
	v4, v6 []int
}

func newPrefixSet(values []string) prefixSet {
	s := prefixSet{items: map[netip.Prefix]struct{}{}}
	b4, b6 := map[int]bool{}, map[int]bool{}
	for _, v := range values {
		p, e := parsePrefix(v)
		if e != nil {
			continue
		}
		s.items[p] = struct{}{}
		if p.Addr().Is4() {
			b4[p.Bits()] = true
		} else {
			b6[p.Bits()] = true
		}
	}
	for n := range b4 {
		s.v4 = append(s.v4, n)
	}
	for n := range b6 {
		s.v6 = append(s.v6, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.v4)))
	sort.Sort(sort.Reverse(sort.IntSlice(s.v6)))
	return s
}
func (s prefixSet) contains(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	bits := s.v6
	if ip.Is4() {
		bits = s.v4
	}
	for _, n := range bits {
		if _, ok := s.items[netip.PrefixFrom(ip, n).Masked()]; ok {
			return true
		}
	}
	return false
}
