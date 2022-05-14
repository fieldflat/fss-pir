package secure_update

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"log"
	"os"
)

type Fss struct {
	// store keys used in fixedBlocks so that they can be sent to the server
	PrfKeys     [][]byte
	FixedBlocks []cipher.Block
	M           uint // used only in multiparty. It is default to 4. If you want to change this, you should also change the size of the CWs in the multiparty keys.
	N           uint
	NumBits     uint   // number of bits in domain
	Temp        []byte // temporary slices so that we only need to allocate memory at the beginning
	Out         []byte
}

const initPRFLen uint = 4

// Structs for keys

type FssKeyEq2P struct {
	SInit   []byte
	TInit   byte
	CW      [][]byte // there are n
	FinalCW int
}

type CWLt struct {
	cs [][]byte
	ct []uint8
	cv []uint
}

type ServerKeyLt struct {
	s  [][]byte
	t  []uint8
	v  []uint
	cw [][]CWLt // Should be length n
}

type FssKeyEqMP struct {
	NumParties uint
	CW         [][]uint32 //Assume CW is 32-bit because f.M is 4. If you change f.M, you should change this
	Sigma      [][]byte
}

type JsonData struct {
	ID           uint `json:"id"`
	AnnualIncome int  `json:"annual_income"`
}

// Helper functions

func randomCryptoInt() uint {
	b := make([]byte, 8)
	rand.Read(b)
	ans, _ := binary.Uvarint(b)
	return uint(ans)
}

// 0th position is the most significant bit
// True if bit is 1 and False if bit is 0
// N is the number of bits in uint
func getBit(n, pos, N uint) byte {
	return byte((n & (1 << (N - pos))) >> (N - pos))
}

// fixed key PRF (Matyas–Meyer–Oseas one way compression function)
// numBlocks represents the number
func prf(x []byte, aesBlocks []cipher.Block, numBlocks uint, temp, out []byte) {
	// If request blocks greater than actual needed blocks, grow output array
	if numBlocks > initPRFLen {
		out = make([]byte, numBlocks*aes.BlockSize)
	}
	for i := uint(0); i < numBlocks; i++ {
		// get AES_k[i](x)
		aesBlocks[i].Encrypt(temp, x)
		// get AES_k[i](x) ^ x
		for j := range temp {
			out[i*aes.BlockSize+uint(j)] = temp[j] ^ x[j]
		}
	}
}

func Restore() {
	f, _ := os.Open("./results/party0")
	defer f.Close()

	var ans0 int
	dec := gob.NewDecoder(f)
	if err := dec.Decode(&ans0); err != nil {
		log.Fatal("decode error:", err)
	}

	f, _ = os.Open("./results/party1")
	defer f.Close()

	var ans1 int
	dec = gob.NewDecoder(f)
	if err := dec.Decode(&ans1); err != nil {
		log.Fatal("decode error:", err)
	}

	fmt.Println("====> answer is ", ans0+ans1)
}
