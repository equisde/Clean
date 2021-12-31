package parse

// All credits go to https://github.com/sgreben/digitalproductid for this

import (
	"bytes"

	"golang.org/x/sys/windows/registry"
)

func binaryToAscii(buffer []byte) string {
	var out bytes.Buffer

	for i := 28; i >= 0; i-- {
		if (29-i)%6 == 0 {
			out.WriteByte('-')
			i--
		}

		out.WriteByte(decodeByte(buffer))
	}

	return string(reverse(out.Bytes()))
}

func decodeByte(buffer []byte) byte {
	var acc int = 0
	const chars = "BCDFGHJKMPQRTVWXY2346789"

	for i := 28; i >= 0; i-- {
		acc *= 256
		acc += int(buffer[i])
		buffer[i] = byte((acc / len(chars) & 0xFF))
		acc %= len(chars)
	}

	return chars[acc]
}

func GetKey() string {
	registryKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Not Valid"
	}
	defer registryKey.Close()

	digitalProductID, _, err := registryKey.GetBinaryValue(`DigitalProductId4`)
	if err != nil {
		return "Not Valid"
	}

	return binaryToAscii(digitalProductID[52:])
}

func reverse(b []byte) []byte {
	for i := len(b)/2 - 1; i >= 0; i-- {
		j := len(b) - 1 - i
		b[i], b[j] = b[j], b[i]
	}
	return b
}
