// Package sha3 implements the SHA-3 algorithms family.

package sha3

import (
	"encoding/binary"
	"hash"
)

const rounds = 24

// b permutation width
const b = 1600

const (
	suffixSHA   = 0x06
	suffixSHAKE = 0x1f
)

// rc round constants
var rc = []uint64{
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008,
}

var piln = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

type keccak struct {
	state     [25]uint64
	size      int
	blockSize int
	buffer    []byte
	suffix    byte
}

func newKeccak(capacity, size int, suffix byte) hash.Hash {
	var h keccak
	h.size = size / 8
	h.blockSize = (b - capacity) / 8
	h.suffix = suffix
	return &h
}

func New224() hash.Hash {
	return newKeccak(224*2, 224, suffixSHA)
}

func New256() hash.Hash {
	return newKeccak(256*2, 256, suffixSHA)
}

func New384() hash.Hash {
	return newKeccak(384*2, 384, suffixSHA)
}

func New512() hash.Hash {
	return newKeccak(512*2, 512, suffixSHA)
}

func SHAKE128(size int) hash.Hash {
	return newKeccak(128*2, size, suffixSHAKE)
}

func SHAKE256(size int) hash.Hash {
	return newKeccak(256*2, size, suffixSHAKE)
}

func (k *keccak) Write(b []byte) (int, error) {
	if len(k.buffer) > 0 {
		x := k.blockSize - len(k.buffer)
		if x > len(b) {
			x = len(b)
		}
		k.buffer = append(k.buffer, b[:x]...)
		b = b[x:]

		if len(k.buffer) < k.blockSize {
			return len(b), nil
		}

		k.absorb(k.buffer)
	}

	for len(b) >= k.blockSize {
		k.absorb(b[:k.blockSize])
		b = b[k.blockSize:]
	}

	k.buffer = b
	return len(b), nil
}

func (k *keccak) Sum(block []byte) []byte {
	k1 := *k
	padded := k1.pad()
	k1.absorb(padded)
	return k1.squeeze(block)
}

func (k *keccak) Reset() {
	k.buffer = nil
	for i := range k.state {
		k.state[i] = 0
	}
}

func (k *keccak) Size() int {
	return k.size
}

func (k *keccak) BlockSize() int {
	return k.blockSize
}

func (k *keccak) absorb(block []byte) {
	if len(block) != k.blockSize {
		panic("invalid block size to absorb")
	}

	for i := 0; i < k.blockSize/8; i++ {
		k.state[i] ^= binary.LittleEndian.Uint64(block[i*8:])

	}
	k.keccakf()
}

func (k *keccak) pad() []byte {
	padded := make([]byte, k.blockSize)
	copy(padded, k.buffer)

	padded[len(k.buffer)] = k.suffix
	padded[len(padded)-1] |= 0x80

	return padded
}

func (k *keccak) squeeze(block []byte) []byte {
	buffer := make([]byte, 8*len(k.state))
	n := k.size
	for {
		for i := range k.state {
			binary.LittleEndian.PutUint64(buffer[i*8:], k.state[i])
		}
		if n <= k.blockSize {
			block = append(block, buffer[:n]...)
			break
		}
		block = append(block, buffer[:k.blockSize]...)
		n -= k.blockSize
		k.keccakf()
	}
	return block
}

func (k *keccak) keccakf() {
	var d uint64
	var bc [5]uint64
	for r := 0; r < rounds; r++ {
		for i := 0; i < 5; i++ {
			bc[i] = k.state[i] ^ k.state[i+5] ^ k.state[i+10] ^ k.state[i+15] ^ k.state[i+20]
		}
		for i := 0; i < 5; i++ {
			// compute the θ effect
			d = bc[(i+4)%5] ^ rol64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				k.state[i+j] ^= d
			}
		}
		d = k.state[1]

		// ρ and π steps
		t := 0
		for i := 0; i < 24; i++ {
			j := piln[i]
			bc[0] = k.state[j]
			t = (t + i + 1) % 64
			k.state[j] = rol64(d, uint64(t))
			d = bc[0]
		}

		// χ step
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = k.state[i+j]
			}
			for i := 0; i < 5; i++ {
				k.state[i+j] ^= (^bc[(i+1)%5]) & bc[(i+2)%5]
			}
		}

		k.state[0] ^= rc[r]
	}
}

func rol64(x, y uint64) uint64 {
	return x<<y | x>>(64-y)
}
