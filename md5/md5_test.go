package md5

import (
	"encoding/hex"
	"testing"
)

type testMD5 struct {
	input string
	md5   string
}

var testMD5Data = []testMD5{
	{
		input: "The quick brown fox jumps over the lazy dog",
		md5:   "9e107d9d372bb6826bd81d3542a419d6",
	},
	{
		input: "The quick brown fox jumps over the lazy dog.",
		md5:   "e4d909c290d0fb1ca068ffaddf22cbd0",
	},
	{
		input: "abc",
		md5:   "900150983cd24fb0d6963f7d28e17f72",
	},
	{
		input: "abcd",
		md5:   "e2fc714c4727ee9395f324cd2e7f331f",
	},
	{
		input: "",
		md5:   "d41d8cd98f00b204e9800998ecf8427e",
	},
}

func TestNew(t *testing.T) {
	for _, d := range testMD5Data {
		h := New()
		h.Write([]byte(d.input))
		r := h.Sum(nil)
		out := hex.EncodeToString(r[:])
		if out != d.md5 {
			t.Errorf("invalid MD5 hash. expected: %s, actual: %s", d.md5, out)
		}
	}
}
