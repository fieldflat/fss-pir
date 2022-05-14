package secure_update

// This file contains the server side code for the FSS library.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	//"fmt"
	"math"
)

// Upon receiving query from client, initialize server with
// this function. The server, unlike the client
// receives prfKeys, so it doesn't need to pick random ones
func ServerInitialize(prfKeys [][]byte, numBits uint) *Fss {
	f := new(Fss)
	f.NumBits = numBits
	f.PrfKeys = make([][]byte, initPRFLen)
	f.FixedBlocks = make([]cipher.Block, initPRFLen)
	for i := range prfKeys {
		f.PrfKeys[i] = make([]byte, aes.BlockSize)
		copy(f.PrfKeys[i], prfKeys[i])
		//fmt.Println("server")
		//fmt.Println(f.PrfKeys[i])
		block, err := aes.NewCipher(f.PrfKeys[i])
		if err != nil {
			panic(err.Error())
		}
		f.FixedBlocks[i] = block
	}
	// Check if int is 32 or 64 bit
	var x uint64 = 1 << 32
	if uint(x) == 0 {
		f.N = 32
	} else {
		f.N = 64
	}
	f.M = 4 // Again default = 4. Look at comments in ClientInitialize to understand this.
	f.Temp = make([]byte, aes.BlockSize)
	f.Out = make([]byte, aes.BlockSize*initPRFLen)

	return f
}

// This is the 2-party FSS evaluation function for point functions.
// This is based on the following paper:
// Boyle, Elette, Niv Gilboa, and Yuval Ishai. "Function Secret Sharing: Improvements and Extensions." Proceedings of the 2016 ACM SIGSAC keyserence on Computer and Communications Security. ACM, 2016.

// Each of the 2 server calls this function to evaluate their function
// share on a value. Then, the client adds the results from both servers.

func (f Fss) EvaluatePF(serverNum byte, k FssKeyEq2P, x uint) int {
	sCurr := make([]byte, aes.BlockSize)
	copy(sCurr, k.SInit)
	tCurr := k.TInit
	for i := uint(0); i < f.NumBits; i++ {
		var xBit byte = 0
		if i != f.N {
			xBit = byte(getBit(x, (f.N - f.NumBits + i + 1), f.N))
		}

		prf(sCurr, f.FixedBlocks, 3, f.Temp, f.Out)
		//fmt.Println(i, sCurr)
		//fmt.Println(i, "f.Out:", f.Out)
		// Keep counter to ensure we are accessing CW correctly
		count := 0
		for j := 0; j < aes.BlockSize*2+2; j++ {
			// Make sure we are doing G(s) ^ (t*sCW||tLCW||sCW||tRCW)
			if j == aes.BlockSize+1 {
				count = 0
			} else if j == aes.BlockSize*2+1 {
				count = aes.BlockSize + 1
			}
			f.Out[j] = f.Out[j] ^ (tCurr * k.CW[i][count])
			count++
		}
		//fmt.Println("xBit", xBit)
		// Pick right seed expansion based on
		if xBit == 0 {
			copy(sCurr, f.Out[:aes.BlockSize])
			tCurr = f.Out[aes.BlockSize] % 2
		} else {
			copy(sCurr, f.Out[(aes.BlockSize+1):(aes.BlockSize*2+1)])
			tCurr = f.Out[aes.BlockSize*2+1] % 2
		}
		//fmt.Println(f.Out)
	}
	sFinal, _ := binary.Varint(sCurr[:8])
	if serverNum == 0 {
		return int(sFinal) + int(tCurr)*k.FinalCW
	} else {
		return -1 * (int(sFinal) + int(tCurr)*k.FinalCW)
	}
}

// This is the 2-party FSS evaluation function for interval functions, i.e. <,> functions.
// The usage is similar to 2-party FSS for equality functions
func (f Fss) EvaluateLt(k ServerKeyLt, x uint) uint {
	xBit := getBit(x, (f.N - f.NumBits + 1), f.N)
	s := make([]byte, aes.BlockSize)
	copy(s, k.s[xBit])
	t := k.t[xBit]
	v := k.v[xBit]
	for i := uint(1); i < f.NumBits; i++ {
		// Get current bit
		if i != f.N {
			xBit = getBit(x, uint(f.N-f.NumBits+i+1), f.N)
		} else {
			xBit = 0
		}
		prf(s, f.FixedBlocks, 4, f.Temp, f.Out)

		// Pick the right values to use based on bit of x
		xStart := int(aes.BlockSize * xBit)
		copy(s, f.Out[xStart:xStart+aes.BlockSize])
		//fmt.Println(s)
		for j := 0; j < aes.BlockSize; j++ {
			s[j] = s[j] ^ k.cw[t][i-1].cs[xBit][j]
		}
		vStart := aes.BlockSize*2 + 8 + 8*xBit
		conv, _ := binary.Uvarint(f.Out[vStart : vStart+8])
		v = v + uint(conv) + k.cw[t][i-1].cv[xBit]
		t = (uint8(f.Out[2*aes.BlockSize+xBit]) % 2) ^ k.cw[t][i-1].ct[xBit]
	}
	return v
}

// This function is for multi-party (3 or more parties) FSS
// for equality functions
// The API interface is similar to the 2 party version.
// One main difference is the output of the evaluation function
// is XOR homomorphic, so for additive queries like SUM and COUNT,
// the client has to add it locally.

func (f Fss) EvaluateEqMP(k FssKeyEqMP, x uint) uint32 {
	p2 := uint(math.Pow(2, float64(k.NumParties-1)))
	mu := uint(math.Ceil(math.Pow(2, float64(f.NumBits)/2) * math.Pow(2, float64(k.NumParties-1)/2)))

	delta := x & ((1 << (f.NumBits / 2)) - 1)
	gamma := (x & (((1 << (f.NumBits + 1) / 2) - 1) << f.NumBits / 2)) >> f.NumBits / 2
	mBytes := f.M * mu

	y := make([]uint32, mu)
	for i := uint(0); i < p2; i++ {
		s := k.Sigma[gamma][i*aes.BlockSize : i*aes.BlockSize+aes.BlockSize]
		all_zero_bytes := true
		for j := uint(0); j < aes.BlockSize; j++ {
			if s[j] != 0 {
				all_zero_bytes = false
				break
			}
		}
		if all_zero_bytes == false {
			numBlocks := uint(math.Ceil(float64(mBytes) / float64(aes.BlockSize)))
			prf(s, f.FixedBlocks, numBlocks, f.Temp, f.Out)
			for k := uint(0); k < mu; k++ {
				tempInt := binary.LittleEndian.Uint32(f.Out[f.M*k : f.M*k+f.M])
				y[k] = y[k] ^ tempInt
			}
			for j := uint(0); j < mu; j++ {
				y[j] = k.CW[i][j] ^ y[j]
			}
		}
	}
	return y[delta]
}

// func Eval() {
// 	fmt.Println("step2: initializing server ...")
// 	f, _ := os.Open("./keys/PrfKeys")
// 	defer f.Close()

// 	var PrfKeys [][]byte
// 	dec := gob.NewDecoder(f)
// 	if err := dec.Decode(&PrfKeys); err != nil {
// 		log.Fatal("decode error:", err)
// 	}

// 	f, _ = os.Open("./keys/NumBits")
// 	defer f.Close()

// 	var NumBits uint
// 	dec = gob.NewDecoder(f)
// 	if err := dec.Decode(&NumBits); err != nil {
// 		log.Fatal("decode error:", err)
// 	}

// 	os.Setenv("SERVER_ID", "0")
// 	f, _ = os.Open("./keys/fssKeys_party" + os.Getenv("SERVER_ID"))
// 	defer f.Close()

// 	var FssKeys_party0 FssKeyEq2P
// 	dec = gob.NewDecoder(f)
// 	if err := dec.Decode(&FssKeys_party0); err != nil {
// 		log.Fatal("decode error:", err)
// 	}

// 	os.Setenv("SERVER_ID", "1")
// 	f, _ = os.Open("./keys/fssKeys_party" + os.Getenv("SERVER_ID"))
// 	defer f.Close()

// 	var FssKeys_party1 FssKeyEq2P
// 	dec = gob.NewDecoder(f)
// 	if err := dec.Decode(&FssKeys_party1); err != nil {
// 		log.Fatal("decode error:", err)
// 	}

// 	fmt.Println("step2: initializing server ...")
// 	fServer := ServerInitialize(PrfKeys, NumBits)
// 	fmt.Println("done. \n")

// 	fmt.Println("step3: evaluating phase ...")
// 	var x uint = 10
// 	fmt.Println("    step3.1: (correct case): input x = ", x)
// 	var ans0, ans1 int = 0, 0
// 	ans0 = fServer.EvaluatePF(0, FssKeys_party0, x)
// 	ans1 = fServer.EvaluatePF(1, FssKeys_party1, x)

// 	f, _ = os.Create("./results/party0")
// 	enc := gob.NewEncoder(f)
// 	if err := enc.Encode(ans0); err != nil {
// 		log.Fatal(err)
// 	}

// 	f, _ = os.Create("./results/party1")
// 	enc = gob.NewEncoder(f)
// 	if err := enc.Encode(ans1); err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Println("    ==> the answer is ", ans0+ans1)

// 	x = 11
// 	fmt.Println("    step3.2: (incorrect case): input x = ", x)
// 	ans0 = fServer.EvaluatePF(0, FssKeys_party0, x)
// 	ans1 = fServer.EvaluatePF(1, FssKeys_party1, x)
// 	fmt.Println("    ==> the answer is ", ans0+ans1)

// 	x = 9
// 	fmt.Println("    step3.3: (incorrect case): input x = ", x)
// 	ans0 = fServer.EvaluatePF(0, FssKeys_party0, x)
// 	ans1 = fServer.EvaluatePF(1, FssKeys_party1, x)
// 	fmt.Println("    ==> the answer is ", ans0+ans1)
// 	fmt.Println("done. \n")
// }

func Eval() {
	fmt.Println("step2: initializing server ...")
	f, _ := os.Open("./keys/PrfKeys")
	defer f.Close()

	var PrfKeys [][]byte
	dec := gob.NewDecoder(f)
	if err := dec.Decode(&PrfKeys); err != nil {
		log.Fatal("decode error:", err)
	}

	f, _ = os.Open("./keys/NumBits")
	defer f.Close()

	var NumBits uint
	dec = gob.NewDecoder(f)
	if err := dec.Decode(&NumBits); err != nil {
		log.Fatal("decode error:", err)
	}

	f, _ = os.Open("./keys/fssKeys_party" + os.Getenv("SERVER_ID"))
	defer f.Close()

	var FssKeys_party FssKeyEq2P
	dec = gob.NewDecoder(f)
	if err := dec.Decode(&FssKeys_party); err != nil {
		log.Fatal("decode error:", err)
	}

	fmt.Println("step2: initializing server ...")
	fServer := ServerInitialize(PrfKeys, NumBits)
	fmt.Println("done. \n")

	fmt.Println("step3: evaluating phase ...")

	bytes, err := ioutil.ReadFile("./jsondata/data" + os.Getenv("SERVER_ID") + ".json")
	if err != nil {
		log.Fatal(err)
	}

	var persons []JsonData
	if err := json.Unmarshal(bytes, &persons); err != nil {
		log.Fatal(err)
	}

	for i, p := range persons {
		fmt.Printf("[i = %d] %d : %d\n", i, p.ID, p.AnnualIncome)
		var server_id, _ = strconv.Atoi(os.Getenv("SERVER_ID"))
		persons[i].AnnualIncome += fServer.EvaluatePF(byte(server_id), FssKeys_party, p.ID)
	}

	outputJson, err := json.MarshalIndent(&persons, "", "    ")
	if err != nil {
		panic(err)
	}
	_ = ioutil.WriteFile("./jsondata/data"+os.Getenv("SERVER_ID")+".json", outputJson, 0755)
}
