package md5

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const size = 16
const blockSize = 64

const (
	a0 = 0x67452301
	b0 = 0xEFCDAB89
	c0 = 0x98BADCFE
	d0 = 0x10325476
)

var K = []uint32{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

// per-round shift amounts
var s = []int{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

type md5 struct {
	state [4]uint32
	x     [blockSize]byte
	nx    int
	len   uint64
}

func New() hash.Hash {
	d := new(md5)
	d.Reset()
	return d
}

func (m *md5) Write(p []byte) (nw int, err error) {
	nw = len(p)
	m.len += uint64(nw)
	if m.nx > 0 {
		n := copy(m.x[m.nx:], p)
		m.nx += n
		if m.nx == blockSize {
			m.rounds(m.x[:])
			m.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= blockSize {
		n := len(p) &^ (blockSize - 1)
		m.rounds(p[:])
		p = p[n:]
	}
	if len(p) > 0 {
		m.nx = copy(m.x[:], p)
	}
	return
}

func (m *md5) rounds(p []byte) {
	a, b, c, d := m.state[0], m.state[1], m.state[2], m.state[3]

	for i := 0; i <= len(p)-blockSize; i += blockSize {
		q := p[i:]
		q = q[:blockSize:blockSize]
		var f, g uint32

		for j := uint32(0); j < blockSize; j++ {
			round := j >> 4
			switch round {
			case 0:
				f = d ^ (b & (c ^ d))
				g = j % 16
			case 1:
				f = c ^ (d & (b ^ c))
				g = (5*j + 1) % 16
			case 2:
				f = b ^ c ^ d
				g = (3*j + 5) % 16
			case 3:
				f = c ^ (b | ^d)
				g = (7 * j) % 16
			}
			a = a + f + le(q[(4*g):]) + K[j]
			a = bits.RotateLeft32(a, s[j])
			a = a + b
			a, b, c, d = d, a, b, c
		}
		a += m.state[0]
		b += m.state[1]
		c += m.state[2]
		d += m.state[3]
	}

	m.state[0], m.state[1], m.state[2], m.state[3] = a, b, c, d
}

func (m *md5) Sum(b []byte) []byte {
	// preprocessing
	m1 := *m
	tmp := [1 + 63 + 8]byte{0x80}
	pad := (55 - m.len) % 64

	binary.LittleEndian.PutUint64(tmp[1+pad:], m.len<<3)
	_, _ = m1.Write(tmp[:1+pad+8])

	if m1.nx != 0 {
		panic("m1.nx != 0")
	}

	var h [size]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(h[4*i:], m1.state[i])
	}
	return append(b, h[:]...)
}

func (m *md5) Size() int {
	return size
}

func (m *md5) BlockSize() int {
	return blockSize
}

func (m *md5) Reset() {
	m.state[0] = a0
	m.state[1] = b0
	m.state[2] = c0
	m.state[3] = d0
	m.nx = 0
	m.len = 0
}

func le(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}
