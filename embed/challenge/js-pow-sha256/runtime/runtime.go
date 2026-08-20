package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"git.gammaspectra.live/git/go-away/lib/challenge/wasm/interface"
	"git.gammaspectra.live/git/go-away/utils/inline"
	"math/bits"
	"strconv"
)

//go:generate tinygo build -target wasip1 -buildmode=c-shared -opt=2 -scheduler=none -gc=leaking -no-debug -o runtime.wasm runtime.go
func main() {

}

func getChallenge(key []byte, params map[string]string) ([]byte, uint64) {
	difficulty := uint64(20)
	var err error
	if diffStr, ok := params["difficulty"]; ok {
		difficulty, err = strconv.ParseUint(diffStr, 10, 64)
		if err != nil {
			panic(err)
		}
	}
	hasher := sha256.New()
	hasher.Write(binary.LittleEndian.AppendUint64(nil, difficulty))
	hasher.Write(key)
	return hasher.Sum(nil), difficulty
}

//go:wasmexport MakeChallenge
func MakeChallenge(in _interface.Allocation) (out _interface.Allocation) {
	return _interface.MakeChallengeDecode(func(in _interface.MakeChallengeInput, out *_interface.MakeChallengeOutput) {
		c, difficulty := getChallenge(in.Key, in.Parameters)

		// create target
		target := make([]byte, len(c))
		nBits := difficulty
		for i := range target {
			var v uint8
			for range 8 {
				v <<= 1
				if nBits == 0 {
					v |= 1
				} else {
					nBits--
				}
			}
			target[i] = v
		}

		dst := make([]byte, inline.EncodedLen(len(c)))
		dst = dst[:inline.Encode(dst, c)]

		targetDst := make([]byte, inline.EncodedLen(len(target)))
		targetDst = targetDst[:inline.Encode(targetDst, target)]

		out.Data = []byte("{\"challenge\": \"" + string(dst) + "\", \"target\": \"" + string(targetDst) + "\", \"difficulty\": " + strconv.FormatUint(difficulty, 10) + "}")
		out.Headers.Set("Content-Type", "application/json; charset=utf-8")
	}, in)
}

//go:wasmexport VerifyChallenge
func VerifyChallenge(in _interface.Allocation) (out _interface.VerifyChallengeOutput) {
	return _interface.VerifyChallengeDecode(func(in _interface.VerifyChallengeInput) _interface.VerifyChallengeOutput {
		c, difficulty := getChallenge(in.Key, in.Parameters)

		result := make([]byte, inline.DecodedLen(len(in.Result)))
		n, err := inline.Decode(result, in.Result)
		if err != nil {
			return _interface.VerifyChallengeOutputError
		}
		result = result[:n]

		if len(result) < 8 {
			return _interface.VerifyChallengeOutputError
		}

		// verify we used same challenge
		if subtle.ConstantTimeCompare(result[:len(result)-8], c) != 1 {
			return _interface.VerifyChallengeOutputFailed
		}

		hash := sha256.Sum256(result)

		var leadingZeroesCount int
		for i := range len(hash) {
			leadingZeroes := bits.LeadingZeros8(hash[i])
			leadingZeroesCount += leadingZeroes
			if leadingZeroes < 8 {
				break
			}
		}

		if leadingZeroesCount < int(difficulty) {
			return _interface.VerifyChallengeOutputFailed
		}

		return _interface.VerifyChallengeOutputOK
	}, in)
}
