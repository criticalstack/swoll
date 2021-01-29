package topology

import "hash/crc64"

var crcTable = crc64.MakeTable(crc64.ECMA)

func hash(s string) uint64 {
	h := crc64.Checksum([]byte(s), crcTable)

	if h == 0 {
		return 1
	}

	return h
}

func hashPath(paths ...string) []uint64 {
	ret := []uint64{hash("/")}

	for _, path := range paths {
		if path == "" {
			return ret
		}

		ret = append(ret, hash(path))
	}

	return ret
}
