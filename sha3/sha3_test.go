package sha3

import (
	"encoding/hex"
	"testing"
)

type testSHA3 struct {
	input    string
	sha3v224 string
	sha3v256 string
	sha3v384 string
	sha3v512 string
}

type testSHAKE struct {
	input    string
	size     int
	shake128 string
	shake256 string
}

var testSHA3Data = []testSHA3{
	{
		input:    "abc",
		sha3v224: "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
		sha3v256: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
		sha3v384: "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
		sha3v512: "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
	},
	{
		input:    "abcd",
		sha3v224: "dd886b5fd8421fb3871d24e39e53967ce4fc80dd348bedbea0109c0e",
		sha3v256: "6f6f129471590d2c91804c812b5750cd44cbdfb7238541c451e1ea2bc0193177",
		sha3v384: "5af1d89732d4d10cc6e92a36756f68ecfbf7ae4d14ed4523f68fc304cccfa5b0bba01c80d0d9b67f9163a5c211cfd65b",
		sha3v512: "6eb7b86765bf96a8467b72401231539cbb830f6c64120954c4567272f613f1364d6a80084234fa3400d306b9f5e10c341bbdc5894d9b484a8c7deea9cbe4e265",
	},
	{
		input:    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
		sha3v224: "b6091c08b046b400e6e03caec49ec3d023c0607db87848919b47ce0b",
		sha3v256: "3706569f9a29d62991ebe62f080ea3fac18034d2fffd23b136c10f7148fceb38",
		sha3v384: "d37238ca41bbf3a5f04680e2f23c6681798678f7b7f4d8a1663507d7c6877cfaf32d76e7c0a8493bda32e499ee8bf904",
		sha3v512: "ece1f8872b4604379799bca9c0f3539315b47ba866d421a39eca1ad661956dee273623f8a5d2432e9a244048b3d11388a241267cdd2a211b5dd67482fc0e8ba5",
	},
	{
		input:    "724627916C50338643E6996F07877EAFD96BDF01DA7E991D4155B9BE1295EA7D21C9391F4C4A41C75F77E5D27389253393725F1427F57914B273AB862B9E31DABCE506E558720520D33352D119F699E784F9E548FF91BC35CA147042128709820D69A8287EA3257857615EB0321270E94B84F446942765CE882B191FAEE7E1C87E0F0BD4E0CD8A927703524B559B769CA4ECE1F6DBF313FDCF67C572EC4185C1A88E86EC11B6454B371980020F19633B6B95BD280E4FBCB0161E1A82470320CEC6ECFA25AC73D09F1536F286D3F9DACAFB2CD1D0CE72D64D197F5C7520B3CCB2FD74EB72664BA93853EF41EABF52F015DD591500D018DD162815CC993595B195",
		sha3v224: "bd401b783b4088714463b26703c7360f079d658e232e57e816969edb",
		sha3v256: "d59666dd1d952278be89bbdaf2a8566e9686633de49da9b0410533e60e835309",
		sha3v384: "7fa52889eb8bd79d8d69e191c03428666f556ec169d1172bd66a68bfaa8ed0622d902e7776d755068de3a3548731c14f",
		sha3v512: "85bcc0bfd53e519c5026771d9e3f3cbf363d408828fe0a564064e434756bbf6feda9baad341a0b251e4972ae11b7ea759ae92746630ffd77882fb3ea9acd18fb",
	},
}

var testSHAKEData = []testSHAKE{
	{
		input:    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
		size:     256,
		shake128: "28e1d757fc91b7e055d01eabee20a50fda48c6bb12c8feab9a929ac55ce1e100",
		shake256: "c1f5adb085c1c3dae1d1740b29c7140416b697c990f2b7aa4a0b2aa93210bc85",
	},
	{
		input:    "724627916C50338643E6996F07877EAFD96BDF01DA7E991D4155B9BE1295EA7D21C9391F4C4A41C75F77E5D27389253393725F1427F57914B273AB862B9E31DABCE506E558720520D33352D119F699E784F9E548FF91BC35CA147042128709820D69A8287EA3257857615EB0321270E94B84F446942765CE882B191FAEE7E1C87E0F0BD4E0CD8A927703524B559B769CA4ECE1F6DBF313FDCF67C572EC4185C1A88E86EC11B6454B371980020F19633B6B95BD280E4FBCB0161E1A82470320CEC6ECFA25AC73D09F1536F286D3F9DACAFB2CD1D0CE72D64D197F5C7520B3CCB2FD74EB72664BA93853EF41EABF52F015DD591500D018DD162815CC993595B195",
		size:     512,
		shake128: "58edb4fc1b322662a57fcb562cb91198ca310179e0f2d43cd143748f39fe053f5070ead68cbcd4086f647a33579c4f73bc7070e2de1700806e62c654cda02627",
		shake256: "c15f4cbbd640ed656d07cb843d4eef3122cd3147c12331fc8c5049ac83e08e342e731843cfd975a6d1e79387bc683af68f110c133782af34982aff2d44e00e0a",
	},
}

func TestNew224(t *testing.T) {
	for _, d := range testSHA3Data {
		h := New224()
		h.Write([]byte(d.input))
		r := h.Sum(nil)
		out := hex.EncodeToString(r[:])
		if out != d.sha3v224 {
			t.Errorf("invalid SHA-3 224 hash. expected: %s, actual: %s", d.sha3v224, out)
		}
	}
}

func TestNew256(t *testing.T) {
	for _, d := range testSHA3Data {
		h := New256()
		h.Write([]byte(d.input))
		r := h.Sum(nil)
		out := hex.EncodeToString(r[:])
		if out != d.sha3v256 {
			t.Errorf("invalid SHA-3 256 hash. expected: %s, actual: %s", d.sha3v256, out)
		}
	}
}

func TestNew384(t *testing.T) {
	for _, d := range testSHA3Data {
		h := New384()
		h.Write([]byte(d.input))
		r := h.Sum(nil)
		out := hex.EncodeToString(r[:])
		if out != d.sha3v384 {
			t.Errorf("invalid SHA-3 384 hash. expected: %s, actual: %s", d.sha3v384, out)
		}
	}
}

func TestNew512(t *testing.T) {
	for _, d := range testSHA3Data {
		h := New512()
		h.Write([]byte(d.input))
		r := h.Sum(nil)
		out := hex.EncodeToString(r[:])
		if out != d.sha3v512 {
			t.Errorf("invalid SHA-3 512 hash. expected: %s, actual: %s", d.sha3v512, out)
		}
	}
}

func TestSHAKE128(t *testing.T) {
	for _, d := range testSHAKEData {
		h := SHAKE128(d.size)
		h.Write([]byte(d.input))
		r := h.Sum(nil)
		out := hex.EncodeToString(r[:])
		if out != d.shake128 {
			t.Errorf("invalid SHAKE-128 hash. expected: %s, actual: %s", d.shake128, out)
		}
	}
}

func TestSHAKE256(t *testing.T) {
	for _, d := range testSHAKEData {
		h := SHAKE256(d.size)
		h.Write([]byte(d.input))
		r := h.Sum(nil)
		out := hex.EncodeToString(r[:])
		if out != d.shake256 {
			t.Errorf("invalid SHAKE-256 hash. expected: %s, actual: %s", d.shake256, out)
		}
	}
}
