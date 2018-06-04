package ledger

import (
	"fmt"
	"testing"

	"github.com/newDAG/crypto"
)

func TestSignBlock(t *testing.T) {
	privateKey, _ := crypto.GenerateECDSAKey()

	block := NewBlock(0, 1,
		[][]byte{
			[]byte("abc"),
			[]byte("def"),
			[]byte("ghi"),
		})

	sig, err := block.Sign(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	res, err := block.Verify(sig)
	if err != nil {
		t.Fatalf("Error verifying signature: %v", err)
	}
	if !res {
		t.Fatal("Verify returned false")
	}
}

func TestAppendSignature(t *testing.T) {
	privateKey, _ := crypto.GenerateECDSAKey()
	pubKeyBytes := crypto.FromECDSAPub(&privateKey.PublicKey)

	block := NewBlock(0, 1,
		[][]byte{
			[]byte("abc"),
			[]byte("def"),
			[]byte("ghi"),
		})

	sig, err := block.Sign(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(sig.ValidatorHex())
	err = block.SetSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	spub := fmt.Sprintf("0x%X", pubKeyBytes)
	fmt.Println(spub)
	blockSignature, err := block.GetSignature(spub)
	if err != nil {
		t.Fatal(err)
	}

	res, err := block.Verify(blockSignature)
	if err != nil {
		t.Fatalf("Error verifying signature: %v", err)
	}
	if !res {
		t.Fatal("Verify returned false")
	}

}
