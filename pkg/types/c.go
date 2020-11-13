package types

import (
	"encoding/binary"
	"reflect"
	"unsafe"
)

func MakeCBytes(data unsafe.Pointer, len int) []byte {
	var bytes []byte

	shdr := (*reflect.SliceHeader)(unsafe.Pointer(&bytes))
	shdr.Cap = int(len)
	shdr.Len = int(len)
	shdr.Data = uintptr(data)

	return bytes
}

func MakeCString(data unsafe.Pointer, len int) string {
	bytes := MakeCBytes(data, len)
	count := 0

	for _, b := range bytes {
		if b == 0 {
			break
		}

		count++
	}

	return string(bytes[:count])
}

func MakeCU64(data unsafe.Pointer) uint64 {
	return binary.LittleEndian.Uint64(MakeCBytes(data, 8))
}

func MakeC64(data unsafe.Pointer) int64 {
	return int64(MakeCU64(data))
}

func MakeCU32(data unsafe.Pointer) uint32 {
	return binary.LittleEndian.Uint32(MakeCBytes(data, 4))
}

func MakeC32(data unsafe.Pointer) int32 {
	return int32(MakeCU32(data))
}
